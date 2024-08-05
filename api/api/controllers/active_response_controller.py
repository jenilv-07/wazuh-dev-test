# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

import asyncio
import time

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
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    
    f_kwargs2 = await ActiveResponseModel.get_kwargs(request, additional_kwargs={'agent_list': "001"})

    dapi2 = DistributedAPI(f=active_response.run_command,
                          f_kwargs=remove_nones_to_dict(f_kwargs2),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    
    task2 = asyncio.create_task(dapi2.distribute_function())
    
    f_kwargs = await ActiveResponseModel.get_kwargs(request, additional_kwargs={'agent_list': "agents_list"})

    dapi = DistributedAPI(f=active_response.run_command,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    
    task = asyncio.create_task(dapi.distribute_function())
    
    for i in range(0, 10):
        logger.info(f'count: {i}, Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}')
        
        if(task2.done()):
            break
        
        if(task.done()):
            logger.info(f'main task is completed.')
        
        if(i == 9):
            logger.info(f'Cancelling task')
            task2.cancel()
                
        await asyncio.sleep(1)
    
    data = raise_if_exc(await task)

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
