""" Utility Functions """
import json
import pandas as pd
from pprint import pprint
from urllib.parse import unquote


BFD_SESSIONS_MAX = 'bfd-sessions-max'
BFD_SESSIONS_TOTAL = 'bfd-sessions-total'
BFD_SESSIONS_UP = 'bfd-sessions-up'


def json_to_csv(data, filename):
    """

    :param data: json data for acl log
    :param filename: full path csv filename to write acl log from json
    :return: no return value
    """
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)


def display_summary(summary_json):
    """
    displays json bfd summary
    :param summary_json: bfd summary json data
    :return: no return value
    """
    print("***** BFD Summary  *****")
    bfd_session_down = int(summary_json[0][BFD_SESSIONS_TOTAL]) - int(summary_json[0][BFD_SESSIONS_UP])
    print("\n BFD SESSIONS TOTAL: {}\n BFD SESSIONS UP: {}\n BFD SESSION DOWN: {}\n BFD SESSIONS MAX: {}\n".format
          (summary_json[0][BFD_SESSIONS_TOTAL], summary_json[0][BFD_SESSIONS_UP], bfd_session_down,
           summary_json[0][BFD_SESSIONS_MAX]))


def display_sessions(session_json):
    """
    displays bfd session data
    :param bdf session_json data
    :return: no return value
    """
    print("***** BFD Sessions ***** ")
    pprint(session_json)
    print("\n")


def url_parse_query(acl_url):
    """ decodes url, parses query out of url and converts it to dictionary

    :param acl_url: url
    :return: query in dictionary format
    """
    print("URL:", acl_url)
    return json.loads(unquote(acl_url).split("query=", 1)[1])
