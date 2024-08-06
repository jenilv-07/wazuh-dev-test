import asyncio
import logging
from aiohttp import web
from multiprocessing import Process, Manager, current_process
import signal

import wazuh.active_response as active_response
from api.encoder import dumps, prettify
from api.models.active_response_model import ActiveResponseModel
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhException

logger = logging.getLogger('wazuh-api')

def run_active_response(request, agent, return_dict, wait_for_complete):
    """Function to run active response command in a separate process."""
    try:
        logger.info(f"Starting process for agent: {agent}")
        f_kwargs = ActiveResponseModel.get_kwargs(request, additional_kwargs={'agent_list': agent})
        logger.info(f"f_kwargs for agent {agent}: {f_kwargs}")

        dapi = DistributedAPI(
            f=active_response.run_command,
            f_kwargs=remove_nones_to_dict(f_kwargs),
            request_type='distributed_master',
            is_async=False,
            wait_for_complete=wait_for_complete,
            logger=logger,
            broadcasting=agent == '*',
            rbac_permissions=request['token_info']['rbac_policies']
        )
        result = dapi.distribute_function()
        return_dict[current_process().name] = result
        logger.info(f"Completed process for agent {agent} with result: {result}")
    except Exception as e:
        return_dict[current_process().name] = str(e)
        logger.error(f"Process for agent {agent} failed with error: {e}")

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
    logger.info("Validating request content type.")
    Body.validate_content_type(request, expected_content_type='application/json')
    logger.info("Request content type validated.")

    timeout = 10  # Timeout duration in seconds
    manager = Manager()
    return_dict = manager.dict()
    processes = []

    # Create processes for each agent
    logger.info(f"Starting processes for agents: {agents_list}")
    for agent in agents_list:
        logger.info(f"Creating process for agent: {agent}")
        p = Process(target=run_active_response, args=(request, agent, return_dict, wait_for_complete), name=agent)
        p.start()
        logger.info(f"Started process {p.name} with PID {p.pid}")
        processes.append(p)

    # Wait for all processes to complete or timeout
    logger.info("Waiting for processes to complete or timeout.")
    for p in processes:
        p.join(timeout)
        if p.is_alive():
            logger.info(f"Process {p.name} exceeded the timeout and will be terminated.")
            p.terminate()
            p.join()

    # Collect results and handle exceptions
    logger.info("Collecting results from processes.")
    results = []
    failed = []
    for process_name, result in return_dict.items():
        if isinstance(result, str) and "error" in result.lower():
            failed.append(process_name)
            logger.error(f"Task for agent {process_name} failed with error: {result}")
        else:
            results.append(result)
            logger.info(f"Task for agent {process_name} completed with data: {result}")

    combined_result = {
        "results": results,
        "failed": failed
    }

    logger.info("Returning combined result.")
    return web.json_response(data=combined_result, status=200, dumps=prettify if pretty else dumps)
