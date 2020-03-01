from netflowbot import NetFlowBot
from lookup import DIRECTION_EGRESS, DIRECTION_INGRESS

def test_bot_output_path():
    assert NetFlowBot.construct_output_path_prefix('1min', DIRECTION_EGRESS, None, None) == 'netflow.1min.egress'
    assert NetFlowBot.construct_output_path_prefix('1h', DIRECTION_EGRESS, None, None) == 'netflow.1h.egress'

    assert NetFlowBot.construct_output_path_prefix('1min', DIRECTION_INGRESS, None, None) == 'netflow.1min.ingress'
    assert NetFlowBot.construct_output_path_prefix('1h', DIRECTION_INGRESS, None, None) == 'netflow.1h.ingress'

    assert NetFlowBot.construct_output_path_prefix('1h', DIRECTION_INGRESS, '123', None) == 'netflow.1h.ingress.entity.123'
    assert NetFlowBot.construct_output_path_prefix('1h', DIRECTION_INGRESS, '123', '321') == 'netflow.1h.ingress.entity.123.if.321'
