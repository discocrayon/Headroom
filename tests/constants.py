"""
Values the whole test suite shares.

A constant belongs here when it means the same thing in every file that uses
it. `ORG_ID` qualifies: sixteen files hand it to code that classifies a source
guard against *this* organization, so a file disagreeing about its value would
not be a variation on the fixture, it would be a different organization.

Account IDs stay local. A repdigit is whatever its test casts it as - the
account under test in one file, a third party in the next - and the local name
is what says which.
"""

ORG_ID = "o-example12345"
