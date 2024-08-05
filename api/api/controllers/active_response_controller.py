import asyncio
import logging
from aiohttp import web

import wazuh.active_response as active_response
from api.encoder import dumps, prettify
from api.models.active_response_model import ActiveResponseModel
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.exception import WazuhException, WazuhError, WazuhResourceNotFound
from wazuh.core.agent import get_agents_info

logger = logging.getLogger('wazuh-api')

async def run_command(request, agents_list: str = '*', pretty: bool = False,
                      wait_for_complete: bool = False) -> web.Response:
    """Runs an Active Response command on a specified list of agents.

    Parameters
    ----------
    request : aiohttp.web.Request
    agents_list : str
        List of agents IDs. All possible values from 000 onwards. Default: '*'
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    aiohttp.web.Response
    """
    Body.validate_content_type(request, expected_content_type='application/json')
    tasks = []
    timeout = 10  # Timeout duration in seconds
    system_agents = get_agents_info()
    result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent'
                                      )

    # Create tasks for each agent
    for agent in agents_list:
        if agent == "000":
            raise WazuhError(1703)
        if agent not in system_agents:
            raise WazuhResourceNotFound(1701)
        f_kwargs = await ActiveResponseModel.get_kwargs(request, additional_kwargs={'agent_list': agent})

        dapi = DistributedAPI(
            f=active_response.run_command,
            f_kwargs=remove_nones_to_dict(f_kwargs),
            request_type='distributed_master',
            is_async=False,
            wait_for_complete=wait_for_complete,
            logger=logger,
            broadcasting=agents_list == '*',
            rbac_permissions=request['token_info']['rbac_policies']
        )

        # Create a task and assign a name to it
        task = asyncio.create_task(dapi.distribute_function())
        task.set_name(agent)
        tasks.append(task)

    # Wait for all tasks to complete or timeout
    done, pending = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.ALL_COMPLETED)

    # Cancel any pending tasks
    for task in pending:
        task.cancel()
        result.add_failed_item(id_=task.get_name(), error="chek the agent connecion in not stabal")

    # Collect results and handle exceptions
    for task in done:
        try:
            data = raise_if_exc(await task)
            logger.info(f"-----------{data}------------")
            result.affected_items.append(task.get_name())
            result.total_affected_items += 1
        except WazuhException as e:
            task_name = task.get_name()
            logger.error(f"{task_name} raised an exception: {e}")
    result.affected_items.sort(key=int)
    # Combine results; here, return all results combined
    combined_result = result

    return web.json_response(data=combined_result, status=200, dumps=prettify if pretty else dumps)
