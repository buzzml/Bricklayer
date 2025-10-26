import pytest
from unittest.mock import patch, MagicMock
from data_processing.config_data import ConfigDataSSH  


@patch("data_processing.config_data.ConnectHandler")
def test_configdata_ssh_dummy(mock_connect):
    dummy_connection = MagicMock()
    dummy_connection.send_command.return_value = "config system\n set hostname TEST\nend\n"
    mock_connect.return_value = dummy_connection

    cd_ssh = ConfigDataSSH("1.2.3.4", "user", "pass", "fortinet")
    lines = list(cd_ssh.get())

    assert any("hostname TEST" in l for l in lines)
    dummy_connection.send_command.assert_called_with("show full-configuration")
    dummy_connection.disconnect.assert_called_once()
