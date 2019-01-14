#!/usr/bin/env python3

import argparse
import base64
import functools
import logging
import re
import sys

logger = logging.getLogger(__name__)


def debugger(func):
    @functools.wraps(func)
    def wrapper(*args):
        logger.debug('calling {function}()'.format(function=func.__name__))
        function_result = func(*args)
        logger.debug('{function} returned {result}'.format(function=func.__name__, result=function_result))

        return function_result
    return wrapper


class CommitMessageSyntaxChecker:
    __MAX_COMMIT_TITLE_LENGTH = 55
    __MAX_COMMIT_SUMMARY_LINE_LENGTH = 65
    __MIN_COMMIT_TITLE_WORDS = 3

    def __init__(self, commit_message):
        if not commit_message:
            raise CommitMessageSyntaxError
        else:
            self.__message = commit_message
            self.__title = commit_message.splitlines()[0]
            self.__description = commit_message.splitlines()[1:]
            self._extend_if_revert_commit()

    def _extend_if_revert_commit(self):
        space_length = 1
        if self.__title.split(" ")[0] == 'Revert':
            self.__MAX_COMMIT_TITLE_LENGTH += len('Revert') + space_length

    @debugger
    def _check_commit_title_length(self):
        if len(self.__title) > self.__MAX_COMMIT_TITLE_LENGTH:
            logger.error('The commit title should be less than {} '
                         'characters in length!'.format(self.__MAX_COMMIT_TITLE_LENGTH))
            return False
        else:
            return True

    @debugger
    def _check_commit_title_word_number(self):
        if len(self.__title.split(" ")) < CommitMessageSyntaxChecker.__MIN_COMMIT_TITLE_WORDS:
            logger.error('The commit title must contain at least {} '
                         'words!'.format(CommitMessageSyntaxChecker.__MIN_COMMIT_TITLE_WORDS))
            return False
        else:
            return True

    @debugger
    def _check_commit_title_ending(self):
        if not re.search('.+[a-z0-9]$', self.__title):
            logger.error('The commit should not end with a punctuation mark!')
            return False
        else:
            return True

    @debugger
    def _check_if_second_line_is_empty(self):
        if len(self.__description) == 0 or self.__description[0]:
            logger.error('Second line should be empty!')
            return False
        else:
            return True

    @debugger
    def _check_commit_description_length(self):
        long_line_not_present = True
        for line in self.__description:
            if len(line) > CommitMessageSyntaxChecker.__MAX_COMMIT_SUMMARY_LINE_LENGTH:
                if long_line_not_present:
                    logger.error('No line in the commit description should be over '
                                 '{} characters long.'.format(CommitMessageSyntaxChecker.__MAX_COMMIT_SUMMARY_LINE_LENGTH))
                logger.error('Please shorten this line: {line}'.format(line=line))
                long_line_not_present = False

        return long_line_not_present

    def check_commit_syntax(self):
        error_free = True
        check_functions = [
            self._check_commit_title_length,
            self._check_commit_title_word_number,
            self._check_commit_title_ending,
            self._check_if_second_line_is_empty,
            self._check_commit_description_length,
        ]

        for check in check_functions:
            if not check():
                error_free = False

        if error_free:
            logger.info('The commit message passed the syntax checker!')
        else:
            raise CommitMessageSyntaxError

    def __repr__(self):
        return 'Verifying commit message:\n{}'.format(self.__message)


class CommitMessageSyntaxError(Exception):
    pass


def parse_arguments(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument('--message',
                        type=str,
                        help='Give commit message in base64 encoded format.')

    parser.add_argument('--debugger',
                        action='store_true',
                        help='Sets the logging level to debug')

    args = parser.parse_args(argv)

    return args


def main(argv=[]):
    args = parse_arguments(argv)
    if args.debugger:
        logger.setLevel('DEBUG')
    else:
        logger.setLevel('INFO')

    try:
        commit_message = args.message
        commit_message = base64.b64decode(commit_message).decode("utf-8")
        check_instance = CommitMessageSyntaxChecker(commit_message)
    except (TypeError, CommitMessageSyntaxError):
        logger.critical('Commit message is missing!')
        return 1

    logger.debug(check_instance)

    try:
        check_instance.check_commit_syntax()
    except CommitMessageSyntaxError:
        return 1


if __name__ == '__main__':
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    exit(main(sys.argv[1:]))
