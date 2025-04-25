## Scenario: Run multiple pktvisors instances using different ports 

## Steps:
- Provide 1 pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord <net>`
- Provide 1 pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord -p 10854 <net>`


## Expected Result:
- Both pktvisor containers must be running (one on port 10853 and one on port 10854)
- Endpoints from pktvisor API must be accessible (port 10853 and 10854)
 