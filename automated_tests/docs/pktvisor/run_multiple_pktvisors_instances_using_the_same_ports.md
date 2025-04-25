## Scenario: Run multiple pktvisors instances using the same ports 

## Steps:
- Provide 1 pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord <net>`
- Provide 1 pktvisor instance using `docker run --net=host -d netboxlabs/pktvisor pktvisord <net>`


## Expected Result:
- The first pktvisor instance provisioned must be running (one on port 10853)
- Second pktvisor container must be exited
 
