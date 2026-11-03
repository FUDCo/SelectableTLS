# Test coverage and further implementation work

This contributor reference maps channel behavior to executable scenarios in
`src/test/java/com/fudco/selectabletls/ConformanceTest.java` (a path relative to
the repository root). It is not required reading for an application developer.
See [the channel contract](../CONTRACT.md) for supported behavior.

The suite includes 57 core scenarios and an isolated forced TLS key-update test.
The `lifecycle` mode repeats interrupted reads and TLS 1.3 output drains.
StressProbe adds concurrent traffic, idle peers, churn, malformed inputs,
expired handshakes and valid traffic after failure. It checks selector-key and
transport cleanup between waves. A passing workload is evidence for the exercised
cases, not exhaustive proof of every scheduling permutation.

The Java specifications for
[SocketChannel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/SocketChannel.html),
[SelectableChannel](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/SelectableChannel.html),
[Selector](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/channels/Selector.html)
and [socket options](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/StandardSocketOptions.html)
are the NIO compatibility reference.

The final column below identifies opportunities for further testing, not a
schedule or a list of unimplemented API features.

| Requirement | Executable coverage | Remaining qualification |
| --- | --- | --- |
| TCP connect/finishConnect and failure | `nonblockingConnect`, `failedConnect` | Simultaneous connect/read/write and cancellation campaigns |
| Partial and scattering/gathering transfer | `nonblockingConnect`, `largeTransfer`, `bufferBoundaries` | Broader randomized buffer combinations |
| Independent reader/writer progress | `concurrentReadWrite`, `blockedOutputDuplex`, `socketStreams` | Sustained multi-connection fairness |
| Interruption and asynchronous closure | `interruptRead`, `asynchronousClose`, `selectorClose`, `nonblockingInterrupt`, `nonblockingConnectInterrupt` | More writer/accept races |
| Mode changes preserve pending I/O | `pendingReadMode`, `pendingWriteMode`, `pendingAcceptMode` | Additional scheduling permutations |
| Application shutdown versus TLS control traffic | `inputShutdown`, `largeTransfer`, `truncatedStream` | Longer shutdown/reconnect churn |
| Graceful close, abort, deadlines | `closeDrainsOutput` for TLS 1.2/1.3, `closeRegistrationGap`, `closePeerDeadline`, `stalledDeadline`, `completedDeadline`, `zeroLinger`, `positiveLinger`, `successfulLinger`, `abortLinger` | Broader nonblocking option combinations |
| Closed-channel and socket state | `closedChannelOperations`, `socketConnectedAfterClose`, `providerClose`, `socketAdapterErrors`, `socketOptions` | Broader option combinations |
| Interests and selected-key retention | `tlsSelection`, `interestTransitions`, `selectionInterestSnapshot` | Concurrent mutation under sustained traffic |
| Selector monitor, callbacks, cancellation and closure | `plaintext`, `selectionCallback`, `selectorMonitor`, `registrationCloseRace`, `maximumSelectTimeout` | Continuous updates and repeated callback/cancel races |
| Native channel coexistence and multiple registrations | `mixedNativeChannels`, `multipleSelectors` | Larger mixed populations |
| Address families | `addressFamily` for INET/INET6 | Additional host/network configurations |
| Authentication | `wrongHostname`, `wrongTrust`, `clientCertificate`, `missingClientCertificate` | Expanded invalid-certificate and malformed-record corpus |
| TLS versions and post-handshake activity | `protocol`, `jsseServer`, `renegotiation`, isolated `key-updates` mode | Broader peer implementations and long-lived sessions |
| Fragmentation and bounds | `fragmentedTransport`, `backpressure`, `taskSaturation` | Storms, slow readers/writers, memory and recovery under load |
| Provider ownership | `providerClose`, `registrationCloseRace` | Repeated creation/shutdown races and resource accounting |

