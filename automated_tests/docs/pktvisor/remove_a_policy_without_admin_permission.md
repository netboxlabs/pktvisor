## Scenario: Remove a policy without admin permission

## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord <net_interface>`
- Try to remove the default policy through a DELETE request on the endpoint: `/api/v1/policies/{name_of_the_policy}`
- Make a get request to the same endpoint

## Expected Result:
- pktvisor instance must be running on port 10853
- User should be able to make the get request  (status code 200) and the default policy must be running
- Response of DELETE request must have 404 (Not Found) as status code and no policy must be removed