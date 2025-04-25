## Scenario: Remove policies using admin permission from pktvisor instance 


--------------
All policies

## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Remove the default policy through a DELETE request on the endpoint: `/api/v1/policies/{name_of_the_policy}`
- Make a get request to the same endpoint

## Expected Result:
- pktvisor instance must be running on port 10853
- User should be able to make the get request  (status code 200) and no policies must be running
- Response of DELETE request must have 204 (No Content) as status code and the default policy must be removed


--------------
One policy


## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Create a policy with all handlers through a post request on the endpoint: `/api/v1/policies`
  - Check our method `generate_pcap_policy_with_all_handlers` on [policies.py](../../features/steps/policies.py) in order to have examples of how to do it
- Remove one of the running policies using a DELETE request on the endpoint: `/api/v1/policies/{name_of_the_policy}`
- Make a get request to the same endpoint


## Expected Result:
- pktvisor instance must be running on port 10853
- User should be able to make the get request  (status code 200) and 1 policy must be running
- Response of DELETE request must have 204 (No Content) as status code and the deleted policy must be removed

