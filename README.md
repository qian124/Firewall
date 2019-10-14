# Firewall
The coding challenge of Illumio 2019 Fall

Design:

Based on the direction and protocol of the rules, I divided them into four groups and maintain a HashMap for each of the group.
Within a group of rules, the key of the HashMap is the port number, the value is a list of long array. The long array has two elements, representing the lower bound and the upper bound of an IP range.

When the class constructor is called, it first reads in the rules, parse the port ranges and IP ranges, and insert to the HashMap each belongs to. After all the rules are read, for each (port, list of IP ranges) pair in the four HashMap, I sort the list by the lower bound of IP range. 

When accep_packet function is called, I first check which group of rules it may obey. Then in that group's HashMap, retrieve the list of valid IP ranges by port if any. Since the list is sorted by lower bound, the smallest lower bound i which is larger than the input IP address can be found by binary search. Then I loop from i back to the start of the list, and check if the input IP is included in any of the ranges.

Test:

I wrote Junit test for the solution and created multiple test cases including:
1. inbound, tcp
2. outbound, tcp
3. inbound, udp
4. outbound, udp
1. port is a number, ip is an address
2. port is a range, ip is a range
3. port is a number, ip is a range
4. port is a range, ip is an address
5. rules overlapping with each other
6. a rule covers all possible ports and all possible IP addresses.

Performance Analysis

Assume the number of input rules is n, then building the constructor takes O(n) time. Although it still takes O(n) space to store the rules, we don't need to store the direction and protocol of each rule, and each distinct port is stored only once. The space performance is better than storing the complete rules naively.

During each call of accept_packet function, it takes O(1) time of retrieve the list of IP ranges, O(logn) time to find the possible ranges which includes the input IP by binary search. Then it takes O(n) time to verify each range until success on worst case. Therefore the overall time complexity is O(n) on worst case. Only constant extra space is used, so the space complexity is O(1).

Optimizations

If I had more time, I would improve the algorithm of storing the rules to improve space and time performance. Specifically, for each entry in each HashMap, I can merge intervals of the list of IP ranges. After merging, large space can be saved by removing duplicated ranges and overlapped ranges on average case. Additionally, when verifying the input IP, it only takes O(logn) time to find the one possible IP range(if any) since there is no overlap among the merged ranges. No further loop needed, therefore the time complexity can be decreased to O(logn) when calling the accept_packet function.

I would also add more test cases that has large inputs.

Team Preference

I prefer platform team and data team, but policy team is also interesting to me.
