#! /usr/bin/env python3.9
# GPL-2.0; bjweeks, MZMcBride; 2011; Rschen7754, 2013; L235, PhantomTech 2022
import asyncio
import collections
import json
import logging
import re
import sqlite3
import sre_constants
import time
from typing import Dict, Tuple, List
from urllib.parse import urlparse

from aiosseclient import aiosseclient
import pydle

import settings

ABUSE_LOG_REGEX = re.compile(r'\(\[\[Special:AbuseLog/(\d+)\|details]]\)')
CHANNEL_URLS: Dict[str, str] = {
    'wikidata.wikipedia': 'www.wikidata',
    'mediawiki.wikipedia': 'www.mediawiki',
    'species.wikipedia': 'species.wikimedia',
    'donate.wikimedia.org': 'donate.wikimedia',
    'outreach.wikipedia': 'outreach.wikimedia',
    'wikimania2013wiki': 'wikimania2013.wikimedia',
    'wikimania2014wiki': 'wikimania2014.wikimedia',
    'wikimediafoundation.org': 'wikimediafoundation',
}

Rule = collections.namedtuple('Rule', 'wiki, type, pattern, channel, ignore')

BotClient = pydle.featurize(
    pydle.features.RFC1459Support,
    pydle.features.TLSSupport,
    pydle.features.IRCv3_1Support,
    pydle.features.ISUPPORTSupport
)


class ReportBot(BotClient):
    rule_list = []
    next_message = 0

    def __init__(self, nickname, sqlite_connection: sqlite3.Connection = None, *args, **kwargs):
        super().__init__(nickname, *args, **kwargs)
        self.sqlite_connection: sqlite3.Connection = sqlite_connection

    def query(self, query: str, params: dict = None) -> List[Tuple]:
        """ Query database

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

    async def sync_channels(self) -> None:
        """ Syncs list of channels bot should be in
        """
        logging.info('Syncing report channels')
        query = 'SELECT name FROM channels'
        channels = set(f'{row[0]}' for row in self.query(query))
        [await self.join(channel) for channel in (channels - self.channels.keys())]
        [await self.part(channel) for channel in (self.channels.keys() - channels)]

    def sync_rules(self) -> None:
        """ Syncs list of rules for the bot
        """
        logging.info('Syncing rules')
        query = 'SELECT wiki, type, pattern, channel, ignore FROM rules ORDER BY ignore DESC'
        self.rule_list = [Rule(*row) for row in self.query(query)]

    async def on_connect(self) -> None:
        """ Called when bot connects to irc server
        """
        await super().on_connect()
        await self.sync_channels()
        self.sync_rules()

    async def get_auth_level(self, source: str) -> int:
        """ Gets authorization level of a user.

        :param source: nick of the user
        :return: 0 is the highest level, increasing numbers
        correspond to decreasing authorization levels. -1 for no match.
        """
        auth_level = -1
        info = await self.whois(source)
        if info['identified'] and info['hostname'] in settings.authorized_users:
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

    async def update_rules(self, channel: str, command: List[str], ignore=False,
                           remove=False) -> str:
        """ Adds or removes a rule

        :param channel: channel the rule forwards to
        :param command: the command given by the user, as a list split on spaces
        :param ignore: if the rule is an ignore rule
        :param remove: if the rule should be removed instead of added
        :return: a message intended for the user
        """
        if not self.is_channel(channel):
            return f'Command {command[0]} must be executed from within a channel'
        elif len(command) < 3:
            return f'!{command[0]} wiki (page|user|summary|log|logsummary|all) [pattern]'
        wiki = command[1]
        rule_type = command[2]

        if rule_type not in ('summary', 'user', 'page', 'log', 'logsummary', 'all'):
            return 'Type must be one of: all, user, summary, page, log, logsummary'

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
                       'WHERE wiki=:wiki AND type=:type AND pattern=:pattern '
                       'AND channel=:channel AND ignore=:ignore',
                       {'wiki': wiki, 'type': rule_type, 'pattern': pattern, 'channel': channel,
                        'ignore': ignore})) > 0
        if remove:
            if exists:
                self.query(
                    'DELETE FROM rules '
                    'WHERE wiki=:wiki AND type=:type AND pattern=:pattern '
                    'AND channel=:channel AND ignore=:ignore',
                    {'wiki': wiki, 'type': rule_type, 'pattern': pattern, 'channel': channel,
                     'ignore': ignore})
                self.sync_rules()
                return 'Rule deleted'
            else:
                return 'No such rule'
        else:
            if exists:
                return 'Rule already exists'
            else:
                self.query(
                    'INSERT OR REPLACE INTO rules VALUES (:wiki,:type,:pattern,:channel,:ignore)',
                    {'wiki': wiki, 'type': rule_type, 'pattern': pattern, 'channel': channel,
                     'ignore': ignore})
                self.sync_rules()
                return 'Rule added'

    async def relay_message(self, channel: str, wiki: str, diff: Dict[str, str]) -> None:
        """ Send a message for diff pre-matched to rule

        :param channel: channel to relay to
        :param wiki: wiki diff is from
        :param diff: diff that matched the rule
        """

        from pydle.features.rfc1459 import protocol
        # The 150 below in protocol.MESSAGE_LENGTH_LIMIT - 150 is arbitrary,
        # several additions to the message are made and counted for length
        # before sending a message.
        # See pydle.features.rfc1459.client.message()
        def build_message(max_len: int = protocol.MESSAGE_LENGTH_LIMIT - 150,
                          summary_shortened: bool = False) -> str:
            """ Builds the message to be sent, possibly trimming summary

            Builds the message, if the length is longer than max_len and trimming the
            summary can make the message shorter than max_len, the summary is trimmed.

            :param max_len: Goal maximum characters in the message
            :param summary_shortened: True if summary has already been shortened
            :return: A message less than max_len in length, if it is possible by trimming
            the summary
            """
            if 'page' in diff:
                message = f'\x0303{diff["user"]}\x0315 ' \
                          f'{"created" if diff["new"] else "edited"} ' \
                          f'\x0314[[\x0307{diff["page"]}\x0314]]\x0315: ' \
                          f'\x0310{diff["summary"]}\x0315{"..." if summary_shortened else ""}' \
                          f' {final_url}'
            elif diff['log'] == 'abusefilter':
                message = f'\x0303{diff["user"]}\x0315 ' \
                          f'triggered a filter ' \
                          f'\x0310{trimmed_summary}\x0315{"..." if summary_shortened else ""} ' \
                          f'https://{base_url}.org/wiki/Special:AbuseLog/{filter_log}'
            else:
                message = f'\x0303{diff["user"]}\x0315 ' \
                          f'{diff["log"]} ' \
                          f'\x0310{diff["summary"]}\x0315{"..." if summary_shortened else ""} ' \
                          f'https://{base_url}.org/wiki/Special:Log/{diff["log"]}'

            if len(message) > max_len:
                if len(message) - len(diff['summary']) + 3 < max_len:
                    diff['summary'] = diff['summary'][:-(len(message) + 3 - max_len)]
                    return build_message(summary_shortened=True)
            return message

        if not self.in_channel(channel):
            await asyncio.sleep(2)  # Give bot chance to (re)connect
            if not self.in_channel(channel):
                logging.error(f'Tried to send a message to a channel bot isn\'t in: {channel}')
                return
        if 'page' in diff:
            if not diff['summary']:
                diff['summary'] = '[no summary]'
            url = urlparse(diff['url'])
            fixed_netloc = CHANNEL_URLS.get(url.netloc.strip('.org'),
                                            url.netloc.strip('.org')) + '.org'
            fixed_url = diff['url'].replace(url.netloc, fixed_netloc)
            final_url = fixed_url.replace('http://', 'https://')
            await self.message(channel, build_message())
        else:
            base_url = CHANNEL_URLS.get(wiki.strip('.org'),
                                        wiki.strip('.org'))
            if diff['log'] == 'abusefilter':
                filter_log = ABUSE_LOG_REGEX.findall(diff['summary'])
                if len(filter_log) > 0:
                    filter_log = filter_log[0]
                else:
                    filter_log = ''
                trimmed_summary = \
                    ABUSE_LOG_REGEX.sub('', ','.join(diff['summary'].split(',')[1:])).strip()
                await self.message(channel, build_message())
            else:
                await self.message(channel, build_message())

    async def list_rules(self, message_target: str, for_channel: str) -> None:
        """ Lists a channels rules

        :param message_target: target to send rules to
        :param for_channel: channel to get rule list for
        """
        rules = [Rule(*row) for row in
                 self.query('SELECT * FROM rules WHERE channel=:channel '
                            'ORDER BY wiki, ignore DESC, type',
                            {'channel': for_channel})]
        await self.message(message_target, f'Rules for {for_channel}')
        [await self.message(message_target,
                            f'{r.wiki} {"IGNORE " if r.ignore else ""}{r.type} {r.pattern}')
         for r in rules]

    async def process_command(self, message_target: str, sender: str, message: str) -> None:
        """ Process bot command

        This method filters out messages that aren't commands so all messages
        received can be sent to it

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
            await self.message(conversation,
                               await self.update_rules(message_target, split_message))
        elif split_message[0] in ('ignore', 'filter'):
            await self.message(conversation,
                               await self.update_rules(message_target, split_message,
                                                       ignore=True))
        elif split_message[0] in ('unstalk', 'unwatch', 'unmatch', 'unrelay', 'drop'):
            await self.message(conversation,
                               await self.update_rules(message_target, split_message,
                                                       remove=True))
        elif split_message[0] in ('unignore', 'dropignore', 'unfilter', 'dropfilter'):
            await self.message(conversation,
                               await self.update_rules(message_target, split_message,
                                                       ignore=True, remove=True))
        elif split_message[0] in ('list', 'ls'):
            await self.list_rules(sender, message_target)
        elif split_message[0] in ('listflood', 'listhere', 'lsflood', 'lshere'):
            await self.list_rules(message_target, message_target)
        elif split_message[0] == 'join':
            if await self.is_authorized(sender, 0):
                if not len(split_message) > 1:
                    await self.message(conversation, '!join (channel)')
                else:
                    self.query('INSERT OR IGNORE INTO channels VALUES (:channel)',
                               {'channel': split_message[1]})
                    await self.join(split_message[1])
        elif split_message[0] in ('part', 'leave'):
            if await self.is_authorized(sender, 0):
                if not len(split_message) > 1:
                    await self.message(conversation, '!part (channel)')
                else:
                    self.query('DELETE FROM channels WHERE name=:channel',
                               {'channel': split_message[1]})
                    await self.part(split_message[1])
        elif split_message[0] == 'help':
            await self.message(message_target,
                               '!(relay|drop|ignore|unignore|list|listflood|join|part|quit)')
        elif split_message[0] == 'quit':
            if await self.is_authorized(sender, 0):
                await self.quit()
                self.eventloop.stop()
        elif split_message[0] == 'listchans':
            if await self.is_authorized(sender, 0):
                await self.message(conversation, 
                                f"Currently in the following channels: {str(list(self.channels.keys()))}")
        elif split_message[0] == 'announce':
            if await self.is_authorized(sender, 0):
                announcement = message[10:]
                for channel in self.channels.keys():
                    await self.message(channel, announcement)
                

    async def on_message(self, target: str, by: str, message: str) -> None:
        """ Called when the bot sees a message

        Message include messages sent in channels that the bot is in
        and message sent directly to the bot

        :param target: message recipient, a nick or channel name
        :param by: message sender
        :param message: the message
        """
        await super().on_channel_message(target, by, message)
        # logging.info(f'{by} -> {target}: {message}')

        await self.process_command(target, by, message)

    async def handle_event_stream(self, data: Dict) -> None:
        """ Called when the bot receives a message from the eventstream

        :param data: data fom the event stream
        """
        if data['$schema'] != '/mediawiki/recentchange/1.0.0':
            logging.error('Unhandled schema')

        wiki = '.'.join(data['server_name'].split('.')[:-1])
        if data['type'] not in ('edit', 'new', 'log'):
            if data['type'] not in ('categorize',):
                logging.info(f'Unknown type {data["type"]}')
            return
        diff = {
            'url': data['meta']['uri'],
            'user': data['user'],
            'summary': data['comment']
        }
        if data['type'] == 'log':
            diff.update({
                'log': data['log_type'],
                'summary': data['log_action_comment']
            })
        else:
            diff.update({
                'page': data['title'],
                'patrolled': '!' if data.get('patrolled', None) else '',
                'new': 'N' if not data['revision'].get('old', None) else '',
                'minor': 'M' if data.get('minor', None) else '',
                'bot': 'B' if data.get('bot', None) else '',
                'diff': data['length']['new'] - data['length'].get('old', 0),
                'url': f"{data['meta']['uri']}?diff={data['revision']['new']}"
            })
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
                else:
                    # if not pattern.search(diff['summary']): Justification unknown
                    continue
            elif rule.type == 'log':
                if 'log' in diff:
                    if not pattern.search(diff['log']):
                        continue
                else:
                    continue
            elif rule.type == 'logsummary':
                if 'log' in diff:
                    if not pattern.search(diff['summary']):
                        continue
                else:
                    continue
            else:
                logging.error(f'Unknown rule type in DB: {rule.type}')
            # Rule should be applied

            # Ignore rules are processed first so a match of any rule means
            # that the bot knows how to handle this event for the matched
            # rule's channel
            ignore.add(rule.channel)
            # If the rule is not an ignore rule, relay the event
            if not rule.ignore:
                await self.relay_message(rule.channel, rule.wiki, diff)

    async def message(self, target, message):
        """ Message channel or user.
        """
        # TODO: Implement better rate control (by waiting until pydle does)
        wait_time = self.next_message - time.time_ns()
        if wait_time > 0:
            await asyncio.sleep(wait_time / 1e9)
        self.next_message = time.time_ns() + 0.5e9  # 0.5 seconds
        await super().message(target, message)

    async def on_data_error(self, exception):
        """ Handle errors
        """
        await super().on_data_error(exception)
        # Proper anti-flooding measures are required however this may
        # need to be done in pydle
        # TODO: Implement better rate control (by waiting until pydle does)
        if 'Excess Flood' in str(exception):
            logging.error(f'Handling flood disconnection: {exception}')
            await self.connect(reconnect=True)
        elif isinstance(exception, ConnectionResetError):
            logging.error(f'Handling connection reset disconnection: {exception}')
            await self.connect(reconnect=True)

    async def monitor_event_stream(self) -> None:
        """ Gets and relays events to the bot
        """
        from aiohttp import ClientPayloadError
        last_id = None
        while True:
            try:
                async for event in aiosseclient(
                        'https://stream.wikimedia.org/v2/stream/recentchange', last_id=last_id):
                    last_id = event.id
                    if event.event != 'message':
                        logging.error(f'Unexpected event from stream {event.event}: {event.data}')
                        return
                    event_data = json.loads(event.data)
                    if event_data['$schema'] == '/mediawiki/recentchange/1.0.0':
                        await self.handle_event_stream(event_data)
                    else:
                        logging.error(f'Unexpected schema from stream {event_data["$schema"]}')
            except ClientPayloadError as e:
                logging.error(f'A developer has lazily worked around an error: {str(e)}')


def main():
    logging.basicConfig(level=logging.INFO)

    logging.info('Connecting to DB')
    with sqlite3.connect(settings.database) as sqlite_con:
        sqlite_tables = \
            set(r[0] for r
                in sqlite_con.execute('SELECT DISTINCT tbl_name FROM sqlite_master;').fetchall())
        if 'rules' not in sqlite_tables:
            logging.info('Creating DB table rules')
            sqlite_con.execute('CREATE TABLE rules ('
                               'wiki text, '
                               'type text, '
                               'pattern text, '
                               'channel text, '
                               'ignore integer, '
                               'UNIQUE(wiki, type, pattern, channel, ignore));')
            sqlite_con.commit()
        if 'channels' not in sqlite_tables:
            logging.info('Creating DB table channels')
            sqlite_con.execute('CREATE TABLE channels(name text, UNIQUE(name));')
            sqlite_con.commit()

        logging.info('Preparing bot')
        loop = asyncio.get_event_loop()
        bot = ReportBot(settings.nickname,
                        fallback_nicknames=settings.fallback_nicknames,
                        realname=settings.realname,
                        sasl_username=settings.report_sasl_username,
                        sasl_password=settings.report_sasl_password,
                        sqlite_connection=sqlite_con,
                        eventloop=loop)
        bot = asyncio.gather(
            bot.connect(hostname=settings.report_network,
                        port=settings.report_port,
                        tls=settings.report_tls,
                        tls_verify=settings.report_verify_tls),
            bot.monitor_event_stream(),
            return_exceptions=True)
        logging.info('Running bot')
        try:
            loop.run_until_complete(bot)
        except RuntimeError as e:  # This is probably the wrong way to make !quit stop the process
            if str(e) == 'Event loop stopped before Future completed.':
                pass
            else:
                raise e
        logging.info('Quit')


if __name__ == '__main__':
    main()
