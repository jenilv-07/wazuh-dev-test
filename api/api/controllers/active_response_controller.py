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
from wazuh.core.results import AffectedItemsWazuhResult

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

    affected_items = []
    failed_items = []
    for task in done:
        try:
            data = await task
            data = raise_if_exc(data)
            
            # Check if there are affected items and extract
            if 'data' in data and 'affected_items' in data['data']:
                affected_items.extend(data['data']['affected_items'])
            
            # Check if there are failed items and extract IDs
            if 'data' in data and 'failed_items' in data['data'] and data['data']['failed_items']:
                for failed_item in data['data']['failed_items']:
                    failed_items.extend(failed_item['id'])
                    
        except Exception as e:
            logger.error(f"Task raised an exception: {e}")

    # Construct the result using the AffectedItemsWazuhResult class
    total_affected_items = len(affected_items)
    total_failed_items = len(failed_items)
    
    # Determine the message based on the result
    if total_affected_items > 0 and total_failed_items == 0:
        message = "AR command was sent to all agents"
    elif total_failed_items > 0 and total_affected_items > 0:
        message = "AR command was not sent to some agents"
    else:
        message = "AR command was not sent to any agent"

    result = AffectedItemsWazuhResult(
        affected_items=affected_items,
        total_affected_items=total_affected_items,
        total_failed_items=total_failed_items,
        all_msg='AR command was sent to all agents',
        some_msg='AR command was not sent to some agents',
        none_msg='AR command was not sent to any agent'
    )

    return web.json_response(data=result.to_dict(), status=200, dumps=prettify if pretty else dumps)
