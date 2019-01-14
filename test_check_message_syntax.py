import base64
import logging
import pytest
from check_message_syntax import parse_arguments, main
from check_message_syntax import CommitMessageSyntaxChecker, CommitMessageSyntaxError


def test_parse_arguments():
    argv = ['--message', 'hs5r67u7']
    assert not parse_arguments(argv).debugger
    assert 'hs5r67u7' == parse_arguments(argv).message


def test_parse_arguments_with_debugger():
    argv = ['--message', 'hs5r67u7', '--debugger']
    assert parse_arguments(argv).debugger
    assert 'hs5r67u7' == parse_arguments(argv).message


def test_if_commit_message_exists():
    with pytest.raises(CommitMessageSyntaxError):
        CommitMessageSyntaxChecker('')


def test_extend_if_revert_commit():
    checker = CommitMessageSyntaxChecker('Revert ci: Test text')
    assert (checker._CommitMessageSyntaxChecker__MAX_COMMIT_TITLE_LENGTH ==
            CommitMessageSyntaxChecker._CommitMessageSyntaxChecker__MAX_COMMIT_TITLE_LENGTH + len('Revert') + 1)


def test_if_not_revert_commit():
    checker = CommitMessageSyntaxChecker('ci: Test text')
    assert (checker._CommitMessageSyntaxChecker__MAX_COMMIT_TITLE_LENGTH ==
            CommitMessageSyntaxChecker._CommitMessageSyntaxChecker__MAX_COMMIT_TITLE_LENGTH)


def test_if_commit_title_is_long(caplog):
    checker = CommitMessageSyntaxChecker('This is a very long, wordy commit title, but it is over 55 characters long.')
    assert not checker._check_commit_title_length()
    assert caplog.records[0].levelno == logging.ERROR


def test_if_commit_title_contains_less_than_three_words():
    checker = CommitMessageSyntaxChecker('Two words')
    assert not checker._check_commit_title_word_number()


def test_if_commit_ends_with_punctoation_mark():
    checker = CommitMessageSyntaxChecker('This title ends with punctoation.')
    assert not checker._check_commit_title_ending()


def test_if_second_line_is_empty():
    checker = CommitMessageSyntaxChecker('''This is the title
This should be an empty line''')
    assert not checker._check_if_second_line_is_empty()


def test_if_commit_description_is_long():
    checker = CommitMessageSyntaxChecker('''This is the title

This sentence must be more than 65 characters long for it to fail the test.''')
    assert not checker._check_commit_description_length()


def test_check_commit_syntax_returns_failure(caplog):
    checker = CommitMessageSyntaxChecker(
        '''Two words

This will fail because of the short title
and it prints an error message.''')
    with pytest.raises(CommitMessageSyntaxError):
        checker.check_commit_syntax()
    assert caplog.records[0].message == 'The commit title must contain at least 3 words!'


def test_main_success(caplog):
    caplog.set_level('INFO')
    message = b'''This is a good commit title

The description lines are not long
and well proportioned.'''

    main(['--message', base64.b64encode(message).decode("utf-8")])
    assert caplog.records[0].levelno == logging.INFO
