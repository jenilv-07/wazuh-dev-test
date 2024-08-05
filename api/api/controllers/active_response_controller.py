# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from aiohttp import web

import wazuh.active_response as active_response
from api.encoder import dumps, prettify
from api.models.active_response_model import ActiveResponseModel
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')

async def run_command(request, agents_list: str = '*', pretty: bool = False,
                      wait_for_complete: bool = False) -> web.Response:
    """Runs an Active Response command on a specified list of agents.

    Parameters
    ----------
    request : connexion.request
    agents_list : str
        List of agents IDs. All possible values from 000 onwards. Default: '*'
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
    """
    Body.validate_content_type(request, expected_content_type='application/json')
    tasks = []
    timeout = 10  # Timeout duration in seconds

    for agent in agents_list:
        f_kwargs = await ActiveResponseModel.get_kwargs(request, additional_kwargs={'agent_list': agent})

        dapi = DistributedAPI(f=active_response.run_command,
                              f_kwargs=remove_nones_to_dict(f_kwargs),
                              request_type='distributed_master',
                              is_async=False,
                              wait_for_complete=wait_for_complete,
                              logger=logger,
                              broadcasting=agents_list == '*',
                              rbac_permissions=request['token_info']['rbac_policies'])

        task = asyncio.create_task(dapi.distribute_function())
        tasks.append(task)

    # Wait for all tasks to complete or timeout
    done, pending = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.ALL_COMPLETED)

    # Cancel any pending tasks
    for task in pending:
        task.cancel()

    # Collect results and handle exceptions
    results = []
    for task in done:
        try:
            data = raise_if_exc(await task)
            results.append(data)
        except Exception as e:
            logger.error(f"Task raised an exception: {e}")

    # Combine results if needed; here, simply take the first result
    combined_result = results[0] if results else {}

    return web.json_response(data=combined_result, status=200, dumps=prettify if pretty else dumps)
