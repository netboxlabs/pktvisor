## Scenario: Create a policy using admin permission with all handlers 
## Steps: 
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Create a policy with all handlers through a post request on the endpoint: `/api/v1/policies`
  - Check our method `generate_pcap_policy_with_all_handlers` on [policies.py](../../features/steps/policies.py) in order to have examples of how to do it
- Make a get request to the same endpoint

## Expected Result: 
- pktvisor instance must be running on port 10853
- Response of post request must have 201 as status code
- 2 policies must be running on the pktvisor instance (the default one and the created one)
