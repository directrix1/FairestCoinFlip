# Fairest Coin Flip #
### Copyright (c) 2014 Edward Flick

## Summary ##

The Fairest Coin Flip protocol describes an agreed upon method for an interested party to perform, document, and verify a coin flip or dice roll in a way which guarantees that no member of the party can skew the outcome in their favor. Provided is a zlib licensed reference implementation in C.

## Software ##

### Dependencies ###

 * [Mozilla NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) for cryptographic signing/verification

## How it Works (WIP) ##

The protocol can work over any transport capable of distributing [Cryptographic Message Syntax (CMS - RFC5652)](http://tools.ietf.org/html/rfc5652) messages. The flow of a dice roll / coin flip goes through 5 phases as follows (shown with three participants: Alice, Bob, and Charlie):

### 1. Proposal 
 * _Alice_ decides to have a Fairest Coin Flip with _Bob_ and _Charlie_
 * _Alice_ creates a MIME encoded *proposal* describing the expiration date (in GMT) as a header field, a random nonce as a header field, the possible outcomes (enumerated and starting at 0) as text body, and the participants' public keys as additional MIME parts like so:
```
MIME-Version: 1.0
Content-Type: multipart/mixed;
  boundary=thisisamimeboundary--
X-Expires: Wed, 17 Sep 2014 13:22:00
X-Nonce: 6734475958795bad76789e5f

0. Go to Joey Joe Joe Joe's Crab Shack
1. Scavenge locally for food
2. Starve

--thisisamimeboundary--
Content-Type: WhateverPublicKeyMIMEMediaTypeAliceUses

AlicesPublicKey
--thisisamimeboundary--
Content-Type: WhateverPublicKeyMIMEMediaTypeBobUses

BobsPublicKey
--thisisamimeboundary--
Content-Type: WhateverPublicKeyMIMEMediaTypeCharlieUses

CharliesPublicKey
--thisisamimeboundary--

```
 * _Alice_ then encapsulates the *proposal* in an unencrypted CMS signed (with her private key) message
 * _Alice_ distributes the *CMS encapsulated proposal* to the other participants (_Bob_ and _Charlie_)

### 2. Calculating Reveals and Proofs
 * _Each participant_ decides they want to participate so they each pick a number, x, (random or otherwise) from the list in the *CMS encapsulated proposal*
 * _Each participant_ then creates a CMS signed *reveal document*, the body of which consists of: the decimal number x followed by a space followed by the *CMS encapsulated proposal*'s signature
 * _Each participant_ then defines their *proof of choice* to be the *reveal document*'s signature

### 3. Distributing Proofs
 * _Each participant_ then distributes their *proof of choice* to the other participants
 * If _any participant_ fails to distribute their *proof of choice* by the Expires time then the *proposal* is **Void** and the process stops (the *proof of choice* is each participant's opt in)

### 4. Distributing Reveals
 * After _every participant_ gets _every other participant_'s *proof of choice* then _each participant_ distributes their *reveal document* to the other participants

### 5. Determining Result
 * If _a participant_ fails to distribute their *reveal document* to the _other participants_ by the Expires time then _that participant_ is considered **Ejected**, no longer considered _a participant_
 * _Each participant_ verifies that _every other participant_'s *proof of choice* signature was generated for _that participant_'s *reveal document*
 * If _any participant_ fails verification then _that participant_ is **Ejected**, no longer considered _a participant_
 * _All participants_ now know the **result** by summing _every non-**Ejected** participants'_ x (from their *reveal document*) modulo the total number of choices

NOTES:
 * To discourage ejections, an independant mediator who is uninterested in the results may be brought in as a participant. They would not need to know the original *proposal*. They only need to know the *CMS encapsulated proposal*'s signature. It should be assumed that this mediator would go last in the reveal, because the last _participant_ in the reveal knows the results before sending out their *reveal document* and can choose to be Ejected rather than reveal.
 * If a participant is Ejected then some context specific action may be taken against that former participant.

