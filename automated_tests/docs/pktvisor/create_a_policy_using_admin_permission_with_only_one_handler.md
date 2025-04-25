## Scenario: Create a policy using admin permission with only one handler 


--------------------
DNS:

## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Create a policy with dns handler through a post request on the endpoint: `/api/v1/policies`
- Make a get request to the same endpoint

## Expected Result:
- pktvisor instance must be running on port 10853
- Response of post request must have 201 as status code
- 2 policies must be running on the pktvisor instance (the default one and the created one)


--------------------
NET:

## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Create a policy with net handler through a post request on the endpoint: `/api/v1/policies`
- Make a get request to the same endpoint

## Expected Result:
- pktvisor instance must be running on port 10853
- Response of post request must have 201 as status code
- 2 policies must be running on the pktvisor instance (the default one and the created one)


--------------------
DHCP:


## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Create a policy with dhcp handler through a post request on the endpoint: `/api/v1/policies`
- Make a get request to the same endpoint

## Expected Result:
- pktvisor instance must be running on port 10853
- Response of post request must have 201 as status code
- 2 policies must be running on the pktvisor instance (the default one and the created one)

--------------------
PCAP:


## Steps:
- Provide a pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord --admin-api <net_interface>`
- Create a policy with pcap handler through a post request on the endpoint: `/api/v1/policies`
- Make a get request to the same endpoint

## Expected Result:
- pktvisor instance must be running on port 10853
- Response of post request must have 201 as status code
- 2 policies must be running on the pktvisor instance (the default one and the created one)