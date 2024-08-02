# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
from wazuh.core import active_response, common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhException, WazuhError, WazuhResourceNotFound
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources

TIMEOUT = 5  # Timeout in seconds

async def send_command(agent_id, command, arguments, custom, alert):
    """Send command to a specific agent asynchronously."""
    try:
        async with WazuhQueue(common.AR_SOCKET) as wq:
            system_agents = await asyncio.to_thread(get_agents_info)
        if agent_id not in system_agents:
            raise WazuhResourceNotFound(1701)
        if agent_id == "000":
            raise WazuhError(1703)
        await asyncio.to_thread(active_response.send_ar_message, agent_id, wq, command, arguments, custom, alert)
        return 'success', agent_id, None
    except WazuhException as e:
        return 'failed', agent_id, e

@expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
async def run_command(agent_list: list = None, command: str = '', arguments: list = None, custom: bool = False,
                      alert: dict = None) -> AffectedItemsWazuhResult:
    """Run AR command in a specific agent asynchronously.

    Parameters
    ----------
    agent_list : list
        Agents list that will run the AR command.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent'
                                      )

    if agent_list:
        tasks = []
        for agent_id in agent_list:
            task = asyncio.create_task(send_command(agent_id, command, arguments, custom, alert))
            task.set_name(agent_id)  # Set the agent_id as the task's name
            tasks.append(task)

        for task in tasks:
            try:
                # Use asyncio.wait_for to enforce timeout
                status, agent_id, error = await asyncio.wait_for(task, timeout=TIMEOUT)
                if status == 'success':
                    result.affected_items.append(agent_id)
                    result.total_affected_items += 1
                else:
                    result.add_failed_item(id_=agent_id, error=error)
            except asyncio.TimeoutError:
                agent_id = task.get_name()  # Retrieve agent_id from the task name
                result.add_failed_item(id_=agent_id, error=WazuhException(f"could not connect to the agnet, Chake the end point connecionn"))
                # Optionally, you can cancel the task here if you want to try and free up resources.
                task.cancel()
            except WazuhException as e:
                agent_id = task.get_name()  # Retrieve agent_id from the task name
                result.add_failed_item(id_=agent_id, error=e)

        result.affected_items.sort(key=int)

    return result
