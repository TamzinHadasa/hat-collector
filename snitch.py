#! /usr/bin/env python3.9
# GPL-2.0; bjweeks, MZMcBride; 2011; Rschen7754, 2013; L235, PhantomTech 2022
import collections
import logging
import re
import sqlite3
import sre_constants
from typing import Set, Dict, Tuple, List
from urllib.parse import urlparse

import pydle

import settings

COLOR_RE = re.compile(r'\x02|\x03(?:\d{1,2}(?:,\d{1,2})?)?')

CHANNEL_URLS: Dict[str, str] = {'wikidata.wikipedia': 'www.wikidata',
                                'mediawiki.wikipedia': 'www.mediawiki',
                                'species.wikipedia': 'species.wikimedia',
                                'donate.wikimedia.org': 'donate.wikimedia',
                                'outreach.wikipedia': 'outreach.wikimedia',
                                'wikimania2013wiki': 'wikimania2013.wikimedia',
                                'wikimania2014wiki': 'wikimania2014.wikimedia',
                                'wikimediafoundation.org': 'wikimediafoundation',
                                }

ACTION_RE = re.compile(r'\[\[(.+)]] (?P<log>.+) {2}\* (?P<user>.+) \* {2}(?P<summary>.+)')

DIFF_RE = re.compile(r'''
    \[\[(?P<page>.*)]]\          # page title
    (?P<patrolled>!)?            # patrolled
    (?P<new>N)?                  # new page
    (?P<minor>M)?                # minor edit
    (?P<bot>B)?\                 # bot edit
    (?P<url>.*)\                 # diff url
    \*\ (?P<user>.*?)\ \*\       # user
    \((?P<diff>[+-]\d*)\)\       # diff size
    ?(?P<summary>.*)             # edit summary
''', re.VERBOSE)

Rule = collections.namedtuple('Rule', 'wiki, type, pattern, channel, ignore')

BotClient = pydle.featurize(pydle.features.RFC1459Support,
                            pydle.features.TLSSupport,
                            pydle.features.IRCv3_1Support,
                            pydle.features.ISUPPORTSupport, )


def strip_formatting(message: str) -> str:
    """Strips colors and formatting from IRC messages"""
    return COLOR_RE.sub('', message)


class ListenReportBot(BotClient):
    def __init__(self, nickname, sqlite_connection: sqlite3.Connection = None, *args, **kwargs):
        super().__init__(nickname, *args, **kwargs)
        self.other_group: Set[ListenReportBot] = set()
        self.sqlite_connection: sqlite3.Connection = sqlite_connection

    def set_other_group(self, other_group: Set['ListenReportBot']) -> None:
        """
        :param other_group: set containing all instances of the ListenBot ReportBot group that are not the same type
        """
        self.other_group: Set[ListenReportBot] = other_group

    def query(self, query: str, params: dict = None) -> List[Tuple]:
        """
        :param query: SQL query to run with user input in the form :name
        :param params: Optional dict of parameters in form {'name': value}
        :return: results of the query
        """
        if not params:
            params = dict()
        if not self.sqlite_connection:
            logging.error('SQLite query attempt without assigned connection')
        logging.info(f'Running query: {query}')
        result = self.sqlite_connection.execute(query, params).fetchall()
        self.sqlite_connection.commit()
        return result

    async def update_channels(self, query: str = None) -> None:
        """ Update list of channels bot should be in

        :param query: SQL query that returns a list of channels, should be automatically determined and not needed
        """
        if isinstance(self, ReportBot):
            logging.info('Syncing report channels')
            query = 'SELECT name FROM channels'
        elif isinstance(self, ListenBot):
            logging.info('Syncing listener channels')
            query = 'SELECT "#" || wiki FROM rules'
        else:
            logging.error('Attempted to update channels for unknown type')
        channels = set(f'{row[0]}' for row in self.query(query))
        [await self.join(channel) for channel in (channels - self.channels.keys())]
        [await self.part(channel) for channel in (self.channels.keys() - channels)]
        if isinstance(self, ListenBot):
            self.update_rule_list()

    async def update_other_group(self) -> None:
        """ Updates channels for all bots in the other group
        """
        for bot in self.other_group:
            await bot.update_channels()

    async def on_connect(self) -> None:
        """ Called when bot connects to irc server
        """
        await super().on_connect()
        await self.update_channels()


class ReportBot(ListenReportBot):
    async def get_auth_level(self, source: str) -> int:
        """ Gets authorization level of a user.

        :param source: nick of the user
        :return: 0 is the highest level, increasing numbers
        correspond to decreasing authorization levels. -1 for no match.
        """
        auth_level = -1
        info = await self.whois(source)
        if info['identified'] and info['account'] in settings.authorized_users:
            auth_level = 0
        return auth_level

    async def is_authorized(self, source: str, req_level: int) -> bool:
        """ Check if source is authorized for req_level

        :param source: nick of user to check
        :param req_level: level required to be authorized
        :return: True if the user is authorized at req_level
        """
        if req_level == -1:
            return True
        auth_level = await self.get_auth_level(source)
        return auth_level != -1 and auth_level <= req_level

    async def update_rules(self, channel: str, command: List[str], ignore=False, remove=False) -> str:
        """ Update rules

        :param channel: channel the rule forwards to
        :param command: the command given by the user, as a list split on spaces
        :param ignore: if the rule is an ignore rule
        :param remove: if the rule should be removed instead of added
        :return: a message intended for the user
        """
        if not self.is_channel(channel):
            return f'Command {command[0]} must be executed from within a channel'
        elif len(command) < 3:
            return f'!{command[0]} wiki (page|user|summary|log|all) [pattern]'
        wiki = command[1]
        rule_type = command[2]

        if rule_type not in ('summary', 'user', 'page', 'log', 'all'):
            return 'Type must be one of: all, user, summary, page, log'

        if rule_type == 'all':
            pattern = ''
        elif rule_type != 'all' and len(command) < 4:
            return f'Rule type {rule_type} requires a pattern'
        else:
            pattern = ' '.join(command[3:])
            try:
                re.compile(pattern)
            except sre_constants.error:
                return 'Invalid pattern'

        exists = len(
            self.query('SELECT * FROM rules '
                       'WHERE wiki=:wiki AND type=:type AND pattern=:pattern AND channel=:channel AND ignore=:ignore',
                       {'wiki': wiki, 'type': rule_type, 'pattern': pattern, 'channel': channel, 'ignore': ignore})) > 0
        if remove:
            if exists:
                self.query(
                    'DELETE FROM rules '
                    'WHERE wiki=:wiki AND type=:type AND pattern=:pattern AND channel=:channel AND ignore=:ignore',
                    {'wiki': wiki, 'type': rule_type, 'pattern': pattern, 'channel': channel, 'ignore': ignore})
                await self.update_other_group()
                return 'Rule deleted'
            else:
                return 'No such rule'
        else:
            if exists:
                return 'Rule already exists'
            else:
                self.query('INSERT OR REPLACE INTO rules VALUES (:wiki,:type,:pattern,:channel,:ignore)',
                           {'wiki': wiki, 'type': rule_type, 'pattern': pattern, 'channel': channel, 'ignore': ignore})
                await self.update_other_group()
                return 'Rule added'

    async def relay_message(self, channel: str, wiki: str, diff: Dict[str, str]) -> None:
        """ Send a message for diff pre-matched to rule

        :param channel: channel to relay to
        :param wiki: wiki diff is from
        :param diff: diff that matched the rule
        """
        if not self.in_channel(channel):
            logging.error('Tried to send a message to a channel bot isn\'t in')
            return
        if 'page' in diff:
            if not diff['summary']:
                diff['summary'] = '[no summary]'
            url = urlparse(diff['url'])
            fixed_netloc = CHANNEL_URLS.get(url.netloc.strip('.org'),
                                            url.netloc.strip('.org')) + '.org'
            fixed_url = diff['url'].replace(url.netloc, fixed_netloc)
            final_url = fixed_url.replace('http://', 'https://')
            await self.message(channel,
                               f'\x0303{diff["user"]}\x0315 '
                               f'{"created" if diff["new"] else "edited"} '
                               f'\x0314[[\x0307{diff["page"]}\x0314]]\x0315: '
                               f'\x0310{diff["summary"]}\x0315 {final_url}')
        else:
            base_url = CHANNEL_URLS.get(wiki.strip('.org'),
                                        wiki.strip('.org'))
            await self.message(channel,
                               f'\x0303{diff["user"]}\x0315 '
                               f'{diff["log"]} '
                               f'\x0310{diff["summary"]}\x0315 '
                               f'https://{base_url}.org/wiki/Special:Log/{diff["log"]}')

    async def process_command(self, message_target: str, sender: str, message: str) -> None:
        """ Process bot command

        This method filters out messages that aren't commands so all messages received can be sent to it

        :param message_target: channel/user where the message was sent to
        :param sender: nick that sent the message
        :param message: the message
        """
        if not message.startswith('!'):
            return
        is_channel_message = self.is_channel(message_target)
        conversation = message_target if is_channel_message else sender
        split_message = message[1:].split(' ')
        auth_level = await self.get_auth_level(sender)

        # Begin command matching
        if split_message[0] in ('authlevel', 'authorizationlevel'):
            await self.message(conversation, f'{sender} auth level is {auth_level}')
        elif split_message[0] in ('whois', 'whowas', 'who'):
            if await self.is_authorized(sender, 0):
                result = None
                try:
                    result = await self.whois(split_message[1])
                except AttributeError:
                    pass
                    '''try:
                        result = await self.whowas(split_message[1])
                    except AttributeError:
                        result = None'''
                if not result:
                    await self.message(conversation, 'User not found')
                    return
                response = ''
                for k, v in result.items():
                    response += f'{k}: {v}\n'
                response.strip('\n')
                await self.message(conversation, response)
        elif split_message[0] in ('stalk', 'watch', 'match', 'relay'):
            if await self.is_authorized(sender, 0):
                await self.message(conversation, await self.update_rules(message_target, split_message))
        elif split_message[0] in ('ignore', 'filter'):
            if await self.is_authorized(sender, 0):
                await self.message(conversation, await self.update_rules(message_target, split_message, ignore=True))
        elif split_message[0] in ('unstalk', 'unwatch', 'unmatch', 'unrelay', 'drop'):
            if await self.is_authorized(sender, 0):
                await self.message(conversation, await self.update_rules(message_target, split_message, remove=True))
        elif split_message[0] in ('unignore', 'dropignore', 'unfilter', 'dropfilter'):
            if await self.is_authorized(sender, 0):
                await self.message(conversation,
                                   await self.update_rules(message_target, split_message, ignore=True, remove=True))
        elif split_message[0] in ('list', 'ls'):
            if await self.is_authorized(sender, 0):
                rules = [Rule(*row) for row in self.query('SELECT * FROM rules WHERE channel=:channel',
                                                          {'channel': message_target})]
                await self.message(sender, f'Rules for {message_target}')
                [await self.message(sender, f'{r.wiki} {r.type} {"IGNORE " if r.ignore else ""}{r.pattern}')
                 for r in rules]
        elif split_message[0] in ('listflood', 'listhere', 'lsflood', 'lshere'):
            if await self.is_authorized(sender, 0):
                rules = [Rule(*row) for row in self.query('SELECT * FROM rules WHERE channel=:channel',
                                                          {'channel': message_target})]
                await self.message(message_target, f'Rules for {message_target}')
                [await self.message(message_target, f'{r.wiki} {r.type} {"IGNORE " if r.ignore else ""}{r.pattern}')
                 for r in rules]
        elif split_message[0] == 'join':
            if await self.is_authorized(sender, 0):
                if not len(split_message) > 1:
                    await self.message(conversation, '!join (channel)')
                else:
                    self.query('INSERT OR IGNORE INTO channels VALUES (:channel)', {'channel': split_message[1]})
                    await self.join(split_message[1])
        elif split_message[0] in ('part', 'leave'):
            if await self.is_authorized(sender, 0):
                if not len(split_message) > 1:
                    await self.message(conversation, '!part (channel)')
                else:
                    self.query('DELETE FROM channels WHERE name=:channel', {'channel': split_message[1]})
                    await self.part(split_message[1])
        elif split_message[0] == 'help':
            if await self.is_authorized(sender, 0):
                await self.message(message_target,
                                   '!(relay|drop|ignore|unignore|list|listflood|join|part|quit)')
        elif split_message[0] == 'quit':
            if await self.is_authorized(sender, 0):
                for bot in self.other_group:
                    await bot.quit()
                await self.quit()

    async def on_message(self, target: str, by: str, message: str) -> None:
        await super().on_channel_message(target, by, message)
        logging.info(f'{by} -> {target}: {message}')

        await self.process_command(target, by, message)


class ListenBot(ListenReportBot):
    rule_list = []

    def update_rule_list(self) -> None:
        """ Perform a SQL query to update list of rules
        """
        self.rule_list = [Rule(*row) for row in self.query('SELECT * FROM rules ORDER BY ignore DESC')]

    async def on_channel_message(self, target: str, by: str, message: str) -> None:
        """ Called when a channel the bot is in receives a message

        :param target: the channel
        :param by: nick of the sender
        :param message: the message
        """
        await super().on_channel_message(target, by, message)
        wiki = target[1:]
        cleaned_message = strip_formatting(message)
        edit_match = DIFF_RE.match(cleaned_message)
        action_match = ACTION_RE.match(cleaned_message)
        match = edit_match or action_match
        if not match:
            logging.info(f'{repr(cleaned_message)} was not matched')
            return
        diff = match.groupdict()
        rule_list = self.rule_list.copy()

        # Begin rule matching
        ignore = set()
        for rule in rule_list:
            if rule.wiki != wiki:
                continue
            if rule.channel in ignore:
                continue
            # Check if rule should be applied
            pattern = re.compile(fr'^{rule.pattern}$', re.I | re.U)
            if rule.type == 'all':
                pass
            elif rule.type == 'summary':
                if not pattern.search(diff['summary']):
                    continue
            elif rule.type == 'user':
                if not pattern.search(diff['user']):
                    continue
            elif rule.type == 'page':
                if 'page' in diff:
                    if not pattern.search(diff['page']):
                        continue
                '''else:  # Justification unknown
                    if not pattern.search(diff['summary']):
                        continue'''
            elif rule.type == 'log':
                if 'log' in diff:
                    if not pattern.search(diff['log']):
                        continue
                else:
                    continue
            # Rule should be applied
            # Don't relay a diff for each rule match
            ignore.add(rule.channel)
            # If the rule is not an ignore rule, relay the diff
            if not rule.ignore:
                for bot in self.other_group:
                    assert isinstance(bot, ReportBot)
                    await bot.relay_message(rule.channel, rule.wiki, diff)


class ListenReportPool(pydle.ClientPool):
    def __init__(self):
        super().__init__()
        self.reporters: Set[ReportBot] = set()
        self.listeners: Set[ListenBot] = set()

    def connect(self, client: (ListenBot, ReportBot), *args, **kwargs) -> None:
        super().connect(client, *args, **kwargs)
        if isinstance(client, ListenBot):
            client.set_other_group(self.reporters)
            self.listeners.add(client)
        if isinstance(client, ReportBot):
            client.set_other_group(self.listeners)
            self.reporters.add(client)


def main():
    logging.basicConfig(level=logging.INFO)

    logging.info('Connecting to DB')
    with sqlite3.connect(settings.database) as sqlite_con:
        sqlite_tables = set(r[0] for r in sqlite_con.execute('SELECT DISTINCT tbl_name FROM sqlite_master;').fetchall())
        if 'rules' not in sqlite_tables:
            sqlite_con.execute('CREATE TABLE rules ('
                               'wiki text, '
                               'type text, '
                               'pattern text, '
                               'channel text, '
                               'ignore integer, '
                               'UNIQUE(wiki, type, pattern, channel, ignore));')
            sqlite_con.commit()
        if 'channels' not in sqlite_tables:
            sqlite_con.execute('CREATE TABLE channels(name text, UNIQUE(name));')
            sqlite_con.commit()

        logging.info('Starting clients')
        pool = ListenReportPool()
        pool.connect(ListenBot(settings.nickname,
                               fallback_nicknames=settings.fallback_nicknames,
                               realname=settings.realname,
                               sqlite_connection=sqlite_con),
                     hostname=settings.listen_network,
                     port=settings.listen_port,
                     tls=settings.listen_tls,
                     tls_verify=settings.listen_verify_tls)
        pool.connect(ReportBot(settings.nickname,
                               fallback_nicknames=settings.fallback_nicknames,
                               realname=settings.realname,
                               sasl_username=settings.report_sasl_username,
                               sasl_password=settings.report_sasl_password,
                               sqlite_connection=sqlite_con),
                     hostname=settings.report_network,
                     port=settings.report_port,
                     tls=settings.report_tls,
                     tls_verify=settings.report_verify_tls)
        pool.handle_forever()
        logging.info('Clients running')


if __name__ == '__main__':
    main()
