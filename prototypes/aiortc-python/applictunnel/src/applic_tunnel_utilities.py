import logging

def concat_topics(strings: [str]) -> str:
    """
    Concat a string list to a MQTT topic string with separator
    :param strings: List with a topic hierarchy
    :return: Topic string
    """
    topic = ''
    for subtopic in strings:
        topic = topic + '/' + subtopic
    # delete first "/"
    topic = topic[1:]
    return topic


def check_valid_topic(topic: str) -> bool:
    """
    Check topic string is valid
    :param topic: topic to check
    :return: return True if topic is valid, else return false
    """
    not_allowed_in_topic = ["/", "+", "#"]

    for i in not_allowed_in_topic:
        if topic.find(i) != -1:
            logging.info(topic + " is no valid topic")
            return False
    return True

SIG_TIMEOUT = 5
"""
Signaling timeout
"""

SIG_DEFAULT_TOPIC = 'mqttsignaling'
"""
Default signaling topic
"""

SIG_DEFAULT_CHANNEL = 'conn1'
"""
Default signaling channel
"""