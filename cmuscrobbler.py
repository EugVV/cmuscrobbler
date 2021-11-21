#!/usr/bin/env python3
# cmuscrobbler.py - Scrobble your Songs that you listened to in Cmus
#    Copyright (C) 2008-2010  David Flatz
#    Copyright (C) 2021  Eugene Vlasov
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import time
import os
import re
import cgitb
import traceback
import logging
from datetime import datetime, timedelta
from urllib.parse import quote, unquote
import mutagen
from mutagen.id3 import ID3
import configparser
from hashlib import md5
import requests

# You can also configure the following variables using ~/.cmuscrobbler.conf,
# see INSTALL.

scrobbler_config = [
    { 'username':      'your last.fm username',
      'password':      '7c6a180b36896a0a8c02787eeafb0e4c',
      'cachefile':     '/path/to/last.fm.cachefile',
      'scrobbler_url': 'http://post.audioscrobbler.com/',
      'pidfile':       '/path/to/last.fm.pidfile',
    },
#    { 'username':      'your libre.fm username',
#      'password':      '6cb75f652a9b52798eb6cf2201057c73',
#      'cachefile':     '/path/to/libre.fm.cachefile',
#      'scrobbler_url': 'http://turtle.libre.fm/',
#      'pidfile':       '/path/to/libre.fm.pidfile',
#    },
#    { 'username':      'your listenbrainz.org username',
#      'password':      '819b0643d6b89dc9b579fdfc9094f28e',
#      'cachefile':     '/path/to/listenbrainz.org.cachefile',
#      'scrobbler_url': 'http://proxy.listenbrainz.org/',
#      'pidfile':       '/path/to/listenbrainz.org.pidfile',
#    },
]

# set this to False if you don't like to use the 'now playing' function
do_now_playing = True

# to get yout passwort start python3 and enter:
# >>> from hashlib import md5
# >>> md5('password'.encode('ascii')).hexdigest()
# '5f4dcc3b5aa765d61d8327deb882cf99'
# for listenbrainz.org use user token instead of password

# set this to False if you don't like to use desktop notifications
notifications = True

debug = False
debuglogfile = '/path/to/logfile'

# --- end of configuration variables ---

class Scrobbler:
    SESSION_ID   = None
    POST_URL     = None
    NOW_URL      = None
    HARD_FAILS   = 0
    LAST_HS      = None   # Last handshake time
    HS_DELAY     = 0      # wait this many seconds until next handshake
    SUBMIT_CACHE = []
    MAX_CACHE    = 5      # keep only this many songs in the cache
    PROTOCOL_VERSION = '1.2'
    __LOGIN      = {}     # data required to login

    class BackendError(Exception):
        "Raised if the AS backend does something funny"
        pass
    class AuthError(Exception):
        "Raised on authencitation errors"
        pass
    class PostError(Exception):
        "Raised if something goes wrong when posting data to AS"
        pass
    class SessionError(Exception):
        "Raised when problems with the session exist"
        pass
    class ProtocolError(Exception):
        "Raised on general Protocol errors"
        pass

    def send_post(self, url, vdata):
        hdrs = {'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Cmus Scrobbler 0.5'}
        try:
            response = requests.post(url, data = vdata, headers = hdrs)
            rsp = response.text.upper().strip()
        except Exception as e:
            raise BackendError(str(e))
        if rsp == 'BADSESSION':
            raise SessionError
        elif rsp.startswith('FAILED'):
            raise PostError(rsp.split(' ', 1)[1].strip() + (' POST = [%r]' % response.url))

    def login(self, user, password, hashpw=False, client=('tst', '1.0'), url='http://post.audioscrobbler.com/'):
        """Authencitate with AS (The Handshake)

        @param user:     The username
        @param password: md5-hash of the user-password
        @param hashpw:   If True, then the md5-hash of the password is performed
                    internally. If set to False (the default), then the module
                    assumes the passed value is already a valid md5-hash of the
                    password.
        @param client:   Client information
                    (see http://www.audioscrobbler.net/development/protocol/ for more info)
        @type  client:   Tuple: (client-id, client-version)
        @param url:      Audioscrobbler URL"""

        self.__LOGIN['hs'] = 'true'
        self.__LOGIN['p']  = self.PROTOCOL_VERSION
        self.__LOGIN['c']  = client[0]
        self.__LOGIN['v']  = client[1]
        self.__LOGIN['u']  = user

        if self.LAST_HS is not None:
            next_allowed_hs = self.LAST_HS + timedelta(seconds=self.HS_DELAY)
            if datetime.now() < next_allowed_hs:
                delta = next_allowed_hs - datetime.now()
                raise ProtocolError("""Please wait another %d seconds until next handshake
(login) attempt.""" % delta.seconds)

        self.LAST_HS = datetime.now()

        tstamp = int(time.time())
        self.__LOGIN['t'] = str(tstamp)

        if hashpw:
            hash_pass = md5(password.encode('utf-8')).hexdigest()
        else:
            hash_pass = password

        token  = md5(("%s%d" % (hash_pass, tstamp)).encode('ascii')).hexdigest()
        self.__LOGIN['a'] = token
        try:
            response = requests.get(url, params = self.__LOGIN)
        except Exception as e:
            self.handle_hard_error()
            raise Exception('Error opening url %s' % url)
        if response:
            lines = response.text.split('\n')
            first = lines[0].strip().upper()
            if first == 'BADAUTH':
                raise AuthError('Bad username/password')
            elif first == 'BANNED':
                raise Exception('''This client-version was banned by Audioscrobbler.
Please contact the author of this module!''')
            elif first == 'BADTIME':
                raise ValueError('''Your system time is out of sync with Audioscrobbler.
Consider using an NTP-client to keep you system time in sync.''')
            elif first.startswith('FAILED'):
                self.handle_hard_error()
                raise BackendError("Authencitation with AS failed. Reason: %s" %
                                   lines[0])
            elif first == 'OK':
                # wooooooohooooooo. We made it!
                self.SESSION_ID = lines[1].strip()
                self.NOW_URL    = lines[2].strip()
                self.POST_URL   = lines[3].strip()
                self.HARD_FAILS = 0
            else:
                # some hard error
                self.handle_hard_error()
        else:
            raise BackendError('Empty response')

    def handle_hard_error(self):
        "Handles hard errors."

        if self.HS_DELAY == 0:
            self.HS_DELAY = 60
        elif self.HS_DELAY < 120*60:
            self.HS_DELAY *= 2
        if self.HS_DELAY > 120*60:
            self.HS_DELAY = 120*60

        self.HARD_FAILS += 1
        if self.HARD_FAILS == 3:
            self.SESSION_ID = None

    def now_playing(self, artist, track, album="", length="", trackno="", mbid="" ):
        """Tells audioscrobbler what is currently running in your player. This won't
        affect the user-profile on last.fm. To do submissions, use the "submit"
        method

        @param artist:  The artist name
        @param track:   The track name
        @param album:   The album name
        @param length:  The song length in seconds
        @param trackno: The track number
        @param mbid:    The MusicBrainz Track ID
        @return: True on success, False on failure"""

        if self.SESSION_ID is None:
            raise AuthError("Please 'login()' first. (No session available)")

        if self.POST_URL is None:
            raise PostError("Unable to post data. Post URL was empty!")

        if length != "" and type(length) != type(1):
            raise TypeError("length should be of type int")

        if trackno != "" and type(trackno) != type(1):
            raise TypeError("trackno should be of type int")

        values = {'s': self.SESSION_ID,
                  'a': artist,
                  't': track,
                  'b': album,
                  'l': length,
                  'n': trackno,
                  'm': mbid }

        self.send_post(self.NOW_URL, values)
        return True

    def submit(self, artist, track, time, source='P', rating="", length="", album="",
               trackno="", mbid="", autoflush=False):
        """Append a song to the submission cache. Use 'flush()' to send the cache to
        AS. You can also set "autoflush" to True.

        From the Audioscrobbler protocol docs:
        ---------------------------------------------------------------------------

        The client should monitor the user's interaction with the music playing
        service to whatever extent the service allows. In order to qualify for
        submission all of the following criteria must be met:

        1. The track must be submitted once it has finished playing. Whether it has
           finished playing naturally or has been manually stopped by the user is
           irrelevant.
        2. The track must have been played for a duration of at least 240 seconds or
           half the track's total length, whichever comes first. Skipping or pausing
           the track is irrelevant as long as the appropriate amount has been played.
        3. The total playback time for the track must be more than 30 seconds. Do
           not submit tracks shorter than this.
        4. Unless the client has been specially configured, it should not attempt to
           interpret filename information to obtain metadata instead of tags (ID3,
           etc).

        @param artist: Artist name
        @param track:  Track name
        @param time:   Time the track *started* playing in the UTC timezone (see
                  datetime.utcnow()).

                  Example: int(time.mktime(datetime.utcnow()))
        @param source: Source of the track. One of:
                  'P': Chosen by the user
                  'R': Non-personalised broadcast (e.g. Shoutcast, BBC Radio 1)
                  'E': Personalised recommendation except Last.fm (e.g.
                       Pandora, Launchcast)
                  'L': Last.fm (any mode). In this case, the 5-digit Last.fm
                       recommendation key must be appended to this source ID to
                       prove the validity of the submission (for example,
                       "L1b48a").
                  'U': Source unknown
        @param rating: The rating of the song. One of:
                  'L': Love (on any mode if the user has manually loved the
                       track)
                  'B': Ban (only if source=L)
                  'S': Skip (only if source=L)
                  '':  Not applicable
        @param length: The song length in seconds
        @param album:  The album name
        @param trackno:The track number
        @param mbid:   MusicBrainz Track ID
        @param autoflush: Automatically flush the cache to AS?
        @return:       True on success, False if something went wrong
        """

        source = source.upper()
        rating = rating.upper()

        if source == 'L' and (rating == 'B' or rating == 'S'):
            raise ProtocolError("""You can only use rating 'B' or 'S' on source 'L'.
See the docs!""")

        if source == 'P' and length == '':
            raise ProtocolError("""Song length must be specified when using 'P' as
source!""")

        if type(time) != type(1):
            raise ValueError("""The time parameter must be of type int (unix
timestamp). Instead it was %s""" % time)

        self.SUBMIT_CACHE.append(
            { 'a': artist,
              't': track,
              'i': time,
              'o': source,
              'r': rating,
              'l': length,
              'b': album,
              'n': trackno,
              'm': mbid
            }
        )

        if autoflush or len(self.SUBMIT_CACHE) >= self.MAX_CACHE:
            return self.flush()
        else:
            return True

    def flush(self, inner_call=False):
        """Sends the cached songs to AS.

        @param inner_call: Internally used variable. Don't touch!"""

        if self.POST_URL is None:
            raise ProtocolError('''Cannot submit without having a valid post-URL. Did
you login?''')

        values = {}

        for i, item in enumerate(self.SUBMIT_CACHE):
            for key in item:
                values[key + "[%d]" % i] = item[key]

        values['s'] = self.SESSION_ID

        self.send_post(self.POST_URL, values)
        self.SUBMIT_CACHE = []
        return True

logger = logging.getLogger('cmuscrobbler')

def log_traceback(exception):
    if not debug:
        return
    for tbline in traceback.format_exc().splitlines():
        logger.debug('%s', tbline)

def get_mbid(file):
    try:
        if mutagen.version >= (1,17):
            f = mutagen.File(file, easy=True)
            mbid = f.get('musicbrainz_trackid', '')
            if not isinstance(mbid, str):
                mbid = mbid[0]
            return str(mbid)
        else:
            audio = ID3(file)
            ufid = audio.get('UFID:http://musicbrainz.org')
            return ufid.data if ufid else ''
    except Exception as e:
        logger.debug('get_mbid failed: %s', e)
        return ''

class CmuScrobbler:

    CLIENTID = ('cmu','1.0')

    def __init__(self):
        self.data = {}
        self.status = None
        self.status_content = None
        self.cue_trim = re.compile('/\\d+$')
        if self.status is None:
            self.status = '/tmp/cmuscrobbler-%s.status' % os.environ['USER']
        self.scrobbler = Scrobbler()

    def get_status(self):
        logger.debug('Main Process initialiated')
        self.read_arguments()
        self.read_file()

        now = int(time.mktime(datetime.now().timetuple()))

        """
            The track must be submitted once it has finished playing. Whether
            it has finished playing naturally or has been manually stopped by
            the user is irrelevant.
        """
        if self.status_content is not None:
            if self.status_content['file'] == self.data['file']:
                if self.data['status'] != 'playing' and os.path.exists(self.status):
                    logger.info('Not playing. Removing statusfile')
                    os.remove(self.status)
            self.submit()

        now_playing = None
        if self.data['status'] == 'playing':
            self.write_file(now)
            now_playing = {
                'artist': self.data['artist'],
                'title': self.data['title'],
                'album': self.data['album'],
                'length': self.data['duration'],
                'trackno': self.data['tracknumber'],
                'file': self.data['file'],
            }
            if notifications:
                self.show_notification(now_playing)
        else:
            if os.path.exists(self.status):
                os.remove(self.status)

        self.commit(now_playing)
        logger.debug('Main Process finished.')

    def show_notification(self, now_playing):
        from plyer import notification
        media_file = now_playing['file']
        if now_playing['file'][0:6] == 'cue://':
            media_file = media_file[6:self.cue_trim.search(media_file).start()]
        try:
            if os.path.exists(os.path.dirname(media_file) + '/cover.jpg'):
                notification.notify(title = now_playing['artist'],
                                    message = now_playing['album'] + ' - ' + now_playing['title'],
                                    timeout = 2,
                                    app_name = 'CMuScrobbler',
                                    app_icon = os.path.dirname(media_file) + '/cover.jpg')
            else:
                notification.notify(title = now_playing['artist'],
                                    message = now_playing['album'] + ' - ' + now_playing['title'],
                                    timeout = 2,
                                    app_name = 'CMuScrobbler')
        except Exception as e:
            logger.debug('Notification show error: %s', e)

    def read_arguments(self):
        for k, v in zip(sys.argv[1::2], sys.argv[2::2]):
            try:
                self.data[k] = v
            except UnicodeDecodeError:
                # if utf-8 fails try with latin1.
                # FIXME: consider making this configurable
                self.data[k] = v
        # self.data will be a hash like this:
        """
        {'album': u'Basics',
         'artist': u'Funny van Dannen',
         'duration': u'147',
         'file': u'/home/david/m/m/+DB/Funny_van_Dannen/Basics/01-Guten_Abend.mp3',
         'status': u'stopped',
         'title': u'Guten Abend',
         'tracknumber': u'1'}
        """
        for field in ['artist', 'title', 'album', 'tracknumber', 'status', 'file']:
            if not field in self.data:
                self.data[field] = ''
        logger.debug('Got Arguments: %s', self.data)


    def read_file(self):
        if not os.path.exists(self.status):
            return
        fo = open(self.status, "r")
        content = fo.read()
        fo.close()
        splcont = content.split("\t")
        while len(splcont) < 7:
            splcont.extend([''])
        (file, artist, title, album, trackno, start, duration) = splcont
        duration = duration.strip()
        self.status_content = {'file': unquote(file),
                               'artist': unquote(artist),
                               'title': unquote(title),
                               'album': unquote(album),
                               'trackno': trackno,
                               'start': int(start),
                               'duration': int(duration)}
        logger.debug('Got statusinfo: %s', self.status_content)


    def write_file(self, start):
        to_write = '\t'.join((
            quote(self.data['file']),
            quote(self.data['artist']),
            quote(self.data['title']),
            quote(self.data['album']),
            self.data['tracknumber'],
            str(start),
            self.data['duration']))
        fo = open(self.status, "w")
        fo.write(to_write)
        fo.write('\n')
        fo.close()
        logger.info('Wrote statusfile.')
        logger.debug('Content: %s', to_write)


    def submit(self):
        #submits track if it got played long enough
        if self.status_content['artist'] == '' or self.status_content['title'] == '':
            logger.info('Not submitting because artist or title is empty')
            return

        now = int(time.mktime(datetime.now().timetuple()))

        """ The track must have been played for a duration of at least 240
            seconds *or* half the track's total length, whichever comes first.
            Skipping or pausing the track is irrelevant as long as the
            appropriate amount has been played.

            The total playback time for the track must be more than 30 seconds.
            Do not submit tracks shorter than this.
        """
        if (self.status_content['duration'] <= 30 or
                now - self.status_content['start'] < min(int(round(self.status_content['duration']/2.0)), 240)):
            logger.info('Not submitting because didn\'t listen to long enough')
            return

        to_write = '\t'.join((
            quote(self.status_content['file']),
            quote(self.status_content['artist']),
            quote(self.status_content['title']),
            str(now),
            'P',
            str(self.status_content['duration']),
            quote(self.status_content['album']),
            self.status_content['trackno']))
        for config in scrobbler_config:
            cachefile = config.get('cachefile')
            if cachefile is None:
                raise Exception('Broken config! Cachefile missing.')
            fp = open(cachefile,'a')
            fp.write(to_write)
            fp.write('\n')
            fp.close()
            logger.info('Attached submit to cachefile %s' % cachefile)
        logger.debug('Content: %s', to_write)

    def commit(self, now_playing=None):
        for config in scrobbler_config:
            pidfile = config.get('pidfile')
            password = config.get('password')
            scrobbler_url = config.get('scrobbler_url')
            username = config.get('username')
            cachefile = config.get('cachefile')
            if ((pidfile is None) or (password is None) or (scrobbler_url is None) or (username is None) or (cachefile is None)):
                raise Exception('Broken config! Something is missing.')

            if os.path.exists(pidfile):
                "commit already running maybe waiting for network timeout or something, doing nothing"
                logger.info('Commit already running. Not commiting. (%s)' % pidfile)
                continue

            logger.debug('Forking')
            pid = os.fork()
            if pid:
                fo = open(pidfile, 'w')
                fo.write(str(pid))
                fo.close()
                logger.debug('Wrote pidfile')
                sys.exit(0)
            else:
                try:
                    self._real_commit(now_playing, cachefile, username, password, scrobbler_url)
                finally:
                    if os.path.exists(pidfile):
                        os.remove(pidfile)
                        logger.debug('Deleted pidfile')


    def _real_commit(self, now_playing, cachefile, username, password, scrobbler_url):
        """this is quite ugly spaghetti code. maybe we could make this a little bit more tidy?"""
        logger.info('Begin scrobbling to %s', scrobbler_url)
        if (not do_now_playing):
            logger.debug('Now playing disabled')
            now_playing = None
        success = False
        submitted = False
        tosubmit = set()
        tosubmitted = set()
        cache_count = 0
        retry_sleep = None
        retry_count = 0
        while not success:
            if retry_sleep is None:
                retry_sleep = 60
            else:
                retry_count = retry_count + 1
                if retry_count > 7:
                    logger.info('Giving up scrobbling to %s', scrobbler_url)
                    break
                logger.info('Sleeping %d minute(s)', retry_sleep / 60)
                time.sleep(retry_sleep)
                retry_sleep = min(retry_sleep * 2, 120 * 60)
            #handshake phase
            logger.debug('Handshake')
            try:
                self.scrobbler.login(username, password, hashpw=False, client=CmuScrobbler.CLIENTID, url=scrobbler_url)
            except Exception as e:
                logger.error('Handshake with %s failed: %s', scrobbler_url, e)
                log_traceback(e)
                continue

            #submit phase
            if os.path.exists(cachefile):
                logger.info('Scrobbling songs to %s', scrobbler_url)
                (_, _, _, _, _, _, _, _, mtime, _) = os.stat(cachefile)
                fo = open(cachefile,'r')
                line = fo.readline()
                while len(line) > 0:
                    (path, artist, track, playtime, source, length, album, trackno) = line.split('\t')
                    trackno = trackno.strip()
                    mbid = get_mbid(unquote(path))
                    tosubmit.add((playtime, artist, track, source, length, album, trackno, mbid))
                    line = fo.readline()
                fo.close()
                logger.info('Read %d songs from cachefile %s', len(tosubmit), cachefile)

                logger.debug('Sorting songlist')
                submitlist = list(tosubmit)
                submitlist.sort(key=lambda x: int(x[0]))
                retry = False
                for (playtime, artist, track, source, length, album, trackno, mbid) in submitlist:
                    if (playtime, artist, track, source, length, album, trackno, mbid) in tosubmitted:
                        logger.debug('Track already submitted or in cache: %s - %s', unquote(artist), unquote(track))
                        continue
                    if cache_count >= 3:
                        logger.info('Flushing. cache_count=%d', cache_count)
                        if self._flush():
                            logger.info('Flush successful.')
                            retry_sleep = None
                            cache_count = 0
                        else:
                            retry = True
                            break
                    sb_success = False
                    for tries in range(1, 4):
                        logger.debug('Try to submit: %s, %s, playtime=%d, source=%s, length=%s, album=%s, trackno=%s, mbid=%s',
                            unquote(artist), unquote(track), int(playtime), source, length, unquote(album), trackno, mbid)
                        try:
                            sb_success = self.scrobbler.submit(unquote(artist), unquote(track),
                                int(playtime),
                                album=unquote(album),
                                mbid=mbid,
                                length=length
                            )
                        except Exception as e:
                            logger.error('Submit error: %s', e)
                            log_traceback(e)
                            sb_success = False
                        if sb_success:
                            tosubmitted.add((playtime, artist, track, source, length, album, trackno, mbid))
                            cache_count += 1
                            logger.info('Submitted. cache_count=%d: %s - %s', cache_count, unquote(artist), unquote(track))
                            break
                        logger.error('Submit failed. Try %d', tries)
                    if not sb_success:
                       retry = True
                       break
                    if cache_count >= 3:
                        logger.info('Flushing. cache_count=%d', cache_count)
                        if self._flush():
                            logger.info('Flush successful.')
                            retry_sleep = None
                            cache_count = 0
                        else:
                            retry = True
                            break
                if retry:
                    logger.error('Restaring')
                    continue

                if cache_count > 0:
                    logger.info('Cache not empty: flushing')
                    if self._flush():
                        logger.info('Flush successful.')
                        retry_sleep = None
                        cache_count = 0
                    else:
                        logger.error('Restarting')
                        continue

                (_, _, _, _, _, _, _, _, newmtime, _) = os.stat(cachefile)
                if newmtime != mtime:
                    logger.info('Cachefile changed since we started. Restarting')
                    continue
                logger.info('Scrobbled all Songs, removing cachefile')
                os.remove(cachefile)

            #now playing phase
            if now_playing is not None and not now_playing['artist'] == '' and not now_playing['title'] == '':
                logger.info('Sending \'Now playing\' to %s', scrobbler_url)
                mbid = get_mbid(now_playing['file'])
                np_success = False
                for tries in range(1, 4):
                    try:
                        if len(now_playing['trackno']) == 0:
                            now_playing['trackno'] = '0'
                        np_success = self.scrobbler.now_playing(
                            now_playing['artist'],
                            now_playing['title'],
                            album=now_playing['album'],
                            length=int(now_playing['length']),
                            trackno=int(now_playing['trackno']),
                            mbid=mbid,
                        )
                    except Exception as e:
                        logger.error('now_playing threw an exception: %s' % e)
                        log_traceback(e)
                        break
                    if np_success:
                        logger.info('\'Now playing\' submitted successfully')
                        retry_sleep = None
                        now_playing = None
                        break
                    logger.error('Sending \'Now playing\' failed. Try %d', tries)
                if not np_success:
                    logger.error('Submitting \'Now playing\' failed. Giving up.')

            success = True
        logger.info('Finished scrobbling to %s', scrobbler_url)

    def _flush(self):
        sb_success = False
        for tries in range(1, 4):
            try:
                sb_success = self.scrobbler.flush()
            except Exception as e:
                logger.error('Flush error: %s', e)
                log_traceback(e)
                sb_success = False
            if sb_success:
                break
            logger.error('Flush failed. try %d', tries)
        return sb_success

def exception_hook(*exc_info):
    if exc_info == ():
        exc_info = sys.exc_info()
    fp = open('%s-error' % debuglogfile, 'a')
    fp.write(cgitb.text(exc_info))
    fp.close()
    logger.critical('ERROR EXIT -- see %s-error for detailed traceback' % debuglogfile)
    for tbline in traceback.format_exc().splitlines():
        logger.debug('%s', tbline)

def read_config():
    global do_now_playing, debug, debuglogfile
    cp = configparser.ConfigParser({'home': os.getenv('HOME')})
    cp.read(os.path.expanduser('~/.cmuscrobbler.conf'))
    if cp.sections():
        scrobbler_config[:] = [dict(cp.items(n)) for n in cp.sections()]
    if 'do_now_playing' in cp.defaults():
        do_now_playing = cp.getboolean('DEFAULT', 'do_now_playing')
    if 'debug' in cp.defaults():
        debug = cp.getboolean('DEFAULT', 'debug')
    if 'debuglogfile' in cp.defaults():
        debuglogfile = cp.get('DEFAULT', 'debuglogfile')
    if 'notifications' in cp.defaults():
        notifications = cp.getboolean('DEFAULT', 'notifications')

def usage():
    print("To use cmuscrobbler.py:")
    print("Use it as status_display_program in cmus")
    print("\n type :set status_display_program=/patch/to/cmuscrobbler.py\n")
    print("Don't forget to add your username and password in the script or in")
    print("~/.cmuscrobbler.conf.")

if __name__ == "__main__":
    read_config()

    if debug:
        FORMAT = "%(asctime)-15s %(process)d %(levelname)-5s: %(message)s"
        logging.basicConfig(filename=debuglogfile, level=logging.DEBUG, format=FORMAT)
        sys.excepthook = exception_hook
    else:
        logging.basicConfig(filename='/dev/null')

    if len(sys.argv) < 2:
        usage()
        sys.exit()
    cs = CmuScrobbler()
    cs.get_status()

