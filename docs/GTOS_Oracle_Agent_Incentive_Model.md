# GTOS Oracle Agent Incentive Model
## Economic Security, Reward, Slashing, Delegation, and Subsidy Specification Draft

**Status:** Draft  
**Target chain:** GTOS  
**Language:** English  
**Scope:** Economic model for GTOS OracleHub and oracle operators, including reward formulas, slashing formulas, delegation economics, subsidy policy, bootstrap plan, and decentralization path.

---

## 1. Purpose

This document defines the incentive layer for **GTOS OracleHub**.

It answers five practical questions:

1. Why would oracle agents and operators join GTOS?
2. Who pays them?
3. How are rewards divided among reporters, proof providers, challengers, and delegators?
4. How are malicious or low-quality participants penalized?
5. Does the GTOS team need to run all oracle agents forever?

The short answer is:

- **Demand-side users pay for results**
- **Protocol treasury may subsidize early growth**
- **Operators earn by producing correct, timely, policy-compliant results**
- **Delegators earn by backing good operators**
- **Challengers earn by exposing bad results**
- **The GTOS team may bootstrap early operators, but should not remain the only operator set long term**

This model is designed to fit GTOS’s existing native direction around agent registration, capability registration, delegation, reputation, and scheduled tasks, which already exist as reserved protocol-level address families in the current design fileciteturn23file0L21-L36. GTOS also already has a minimum stake concept for agents via `AgentMinStake`, which is a natural anchor for oracle operator staking policy fileciteturn23file0L39-L45.

---

## 2. Core Economic Principle

OracleHub is a **two-sided market**:

- **Demand side** wants trustworthy outcomes
- **Supply side** provides those outcomes

Demand side includes:

- prediction markets
- event-resolution markets
- scalar-statistics markets
- task settlement protocols
- insurance or treasury automations
- AI agent applications

Supply side includes:

- oracle reporters
- evidence providers
- proof providers
- challengers
- aggregators
- delegators

The protocol works only if the expected profit for good participants is positive:

```text
Expected Profit(operator)
  = Expected Rewards(operator)
  - Expected Costs(operator)
  - Expected Penalties(operator)
```

The protocol should be parameterized so that:

```text
Expected Rewards(good operator)
  > Expected Costs(good operator)
```

and

```text
Expected Rewards(bad operator)
  - Expected Penalties(bad operator)
  < 0
```

That is the economic heart of OracleHub.

---

## 3. Roles in the Incentive System

## 3.1 Query payer
The entity that funds a query or market resolution.

Examples:

- a prediction market factory
- a specific market creator
- a protocol treasury
- an application subscribing to oracle service

## 3.2 Oracle operator
A staked participant that produces reports and/or proofs.

Subtypes:

- reporter
- validator
- challenge responder
- proof submitter
- aggregator

## 3.3 Delegator
A passive capital provider who delegates stake to an operator.

## 3.4 Challenger
A participant who posts a bond and challenges a faulty result.

## 3.5 Bootstrap operator
An operator run or sponsored by the GTOS team during early network growth.

## 3.6 Protocol treasury
The treasury that may subsidize participation in the early stages or support strategic query classes.

---

## 4. Revenue Sources

An oracle operator should be able to earn from multiple revenue channels.

## 4.1 Query reward

Each query or market resolution round may escrow a reward pool:

```text
QueryRewardPool(q)
```

This pool is the primary direct revenue source for oracle operators.

Examples:

- a binary event market pays for event resolution
- a scalar market pays for official statistic retrieval
- a task-settlement query pays for verdict resolution

## 4.2 Protocol subsidy

In the bootstrap phase, GTOS may pay a subsidy:

```text
ProtocolSubsidy(q)
```

This should be used to ensure participation while demand is still immature.

## 4.3 Proof premium

High-assurance rounds may require more expensive work:

- authenticated source proofs
- TEE attestation
- zk-aggregated committee proof
- zkML classifier proof

These rounds should include an explicit premium:

```text
ProofPremium(q)
```

## 4.4 Reputation bonus

Operators with strong historical performance may earn a multiplier:

```text
ReputationMultiplier(i)
```

where `i` is the operator.

## 4.5 Delegation fees

Operators may charge a commission on delegator-backed rewards:

```text
OperatorCommission(i)
```

---

## 5. Cost Model

An operator incurs real costs.

## 5.1 Operational cost

```text
OpCost(i, q)
```

Includes:

- server cost
- bandwidth
- storage
- node maintenance
- monitoring

## 5.2 Data acquisition cost

```text
DataCost(i, q)
```

Includes:

- API subscriptions
- premium data feeds
- web crawling
- official source access

## 5.3 Inference / model cost

```text
ModelCost(i, q)
```

Includes:

- LLM usage
- classifier inference
- summarization pipelines
- normalization logic

## 5.4 Proof generation cost

```text
ProofCost(i, q)
```

Includes:

- zk proof generation
- TEE attestation overhead
- authenticated source proof generation

## 5.5 Capital cost of stake

```text
CapitalCost(i)
```

This reflects the opportunity cost of locking stake.

---

## 6. Reward Formula

Define:

- `q`: query / round
- `i`: operator
- `W_i(q)`: participation weight of operator `i`
- `Correct_i(q)`: 1 if operator result is accepted as correct, else 0
- `OnTime_i(q)`: 1 if submission is on time, else 0
- `PolicyOK_i(q)`: 1 if source/policy/proof requirements are satisfied, else 0
- `ProofBonusEligible_i(q)`: 1 if operator supplied a qualifying proof contribution, else 0

Let:

```text
BasePool(q) = QueryRewardPool(q) + ProtocolSubsidy(q)
```

Then define the reward share weight:

```text
RewardWeight_i(q)
  = W_i(q)
    * Correct_i(q)
    * OnTime_i(q)
    * PolicyOK_i(q)
    * ReputationMultiplier(i)
```

Total accepted reward weight:

```text
TotalRewardWeight(q)
  = Σ RewardWeight_j(q)
```

Base operator reward:

```text
BaseReward_i(q)
  = BasePool(q) * RewardWeight_i(q) / TotalRewardWeight(q)
```

Proof bonus:

```text
ProofReward_i(q)
  = ProofPremium(q) * ProofShare_i(q)
```

where:

```text
Σ ProofShare_i(q) = 1
```

Total operator reward:

```text
TotalReward_i(q)
  = BaseReward_i(q) + ProofReward_i(q)
```

---

## 7. Weight Definitions

OracleHub may support multiple weighting modes.

## 7.1 Count-weighted mode

```text
W_i(q) = 1
```

Suitable only for early test deployments.

## 7.2 Stake-weighted mode

```text
W_i(q) = EffectiveStake_i
```

where:

```text
EffectiveStake_i = SelfStake_i + DelegatedStake_i
```

## 7.3 Reputation-weighted mode

```text
W_i(q) = EffectiveStake_i * RepScore_i
```

## 7.4 Capped hybrid mode

To prevent very large operators from dominating:

```text
W_i(q) = min(EffectiveStake_i, StakeCap(q)) * RepScore_i
```

This is the recommended production formula.

---

## 8. Reputation Multiplier

Let operator reputation be normalized into:

```text
RepNorm_i ∈ [0, 1]
```

Then define:

```text
ReputationMultiplier(i)
  = 1 + α * RepNorm_i
```

where:

- `α` is a protocol parameter
- recommended `α ∈ [0.1, 0.5]`

Example:

- `RepNorm_i = 0.8`
- `α = 0.25`

then:

```text
ReputationMultiplier(i) = 1.2
```

This gives good operators moderate reward uplift without allowing reputation to dominate everything.

---

## 9. Query Funding Model

A query should define its funding composition explicitly.

```text
TotalFunding(q)
  = UserPaidReward(q)
  + AppPaidReward(q)
  + TreasurySubsidy(q)
  + ProofPremium(q)
  + ChallengeReserve(q)
```

### Components

- `UserPaidReward(q)`: paid by the creator or market
- `AppPaidReward(q)`: paid by a protocol or subscriber
- `TreasurySubsidy(q)`: paid by GTOS treasury during bootstrap
- `ProofPremium(q)`: extra budget for expensive proof modes
- `ChallengeReserve(q)`: reserved budget to reward successful challengers

### Recommendation

In steady state:

```text
TreasurySubsidy(q) -> 0
```

for ordinary market classes, while premium or strategic classes may continue to receive subsidy.

---

## 10. Demand-Side Payers

The answer to “who pays oracle agents?” is not singular.

## 10.1 Market creator pays
The most natural model.

For a prediction market:

- the market factory creates the market
- the market factory also funds the oracle resolution pool

## 10.2 Application pays
A consumer protocol subscribes to recurring oracle service.

Examples:

- macro-stat feed
- sports-result feed
- event-detection feed
- task-verdict feed

## 10.3 Protocol treasury pays
Bootstrap or strategic sponsorship.

Use cases:

- new query class onboarding
- under-supplied but important categories
- phase III proof piloting
- public-good oracle markets

---

## 11. Subsidy Policy

Subsidy must be explicit, formula-driven, and temporary where possible.

## 11.1 Bootstrap subsidy formula

Let:

- `DemandScore(q)` reflect observable demand
- `StrategicClass(q)` be 1 if the query is strategic
- `ProofMode(q)` be the selected proof mode

A simple subsidy formula:

```text
TreasurySubsidy(q)
  = S_base
  + S_strategic * StrategicClass(q)
  + S_proof * ProofModeMultiplier(q)
  - S_demand * DemandScore(q)
```

Where:

- `S_base` is a minimum bootstrap amount
- `S_strategic` boosts strategic categories
- `S_proof` supports high-proof modes
- `S_demand` reduces subsidy as user demand increases

## 11.2 Demand score example

```text
DemandScore(q)
  = β1 * log(1 + HistoricalPaidQueries(class(q)))
  + β2 * log(1 + UserPaidReward(q))
```

As real market demand rises, subsidy falls automatically.

## 11.3 Subsidy sunset policy

For ordinary market classes:

```text
if RollingUserPaidCoverage(class) >= CoverageThreshold
then TreasurySubsidy(class) = 0
```

Example:

- if users pay at least 80% of the total required reward for 90 consecutive days
- protocol subsidy for that class is phased out

---

## 12. Delegation Economics

Delegation allows passive capital providers to back high-quality operators.

## 12.1 Effective stake

```text
EffectiveStake_i = SelfStake_i + DelegatedStake_i
```

## 12.2 Operator commission

Each operator sets:

```text
Commission_i ∈ [0, CommissionMax]
```

where `CommissionMax` is a protocol cap.

## 12.3 Delegator reward formula

Let operator `i` have total net distributable reward:

```text
NetOperatorReward_i(q)
  = TotalReward_i(q) - Penalty_i(q)
```

Operator commission cut:

```text
OperatorCommissionCut_i(q)
  = Commission_i * DelegatedPortion_i(q)
```

A simpler implementation is:

```text
DelegatorPool_i(q)
  = max(NetOperatorReward_i(q), 0) * DelegatedStake_i / EffectiveStake_i
```

```text
OperatorPool_i(q)
  = max(NetOperatorReward_i(q), 0) - DelegatorPool_i(q)
```

Then the operator takes commission from the delegator pool:

```text
CommissionTake_i(q)
  = Commission_i * DelegatorPool_i(q)
```

Delegators receive:

```text
DelegatorNetPool_i(q)
  = DelegatorPool_i(q) - CommissionTake_i(q)
```

Each delegator `d` backing operator `i` receives:

```text
DelegatorReward_{d,i}(q)
  = DelegatorNetPool_i(q) * DelegatedStake_{d,i} / DelegatedStake_i
```

Operator final retained reward:

```text
OperatorFinalReward_i(q)
  = OperatorPool_i(q) + CommissionTake_i(q)
```

---

## 13. Slashing Model

Slashing exists to make dishonest or negligent behavior economically unattractive.

## 13.1 Penalty classes

Define three penalty classes:

- light
- medium
- heavy

## 13.2 Light slash

For:

- commit without reveal
- late reveal
- malformed but non-malicious payload
- missing metadata fields

Formula:

```text
LightSlash_i(q)
  = λ1 * SlashableStake_i
```

where `λ1` is small, for example 0.1% to 1%.

## 13.3 Medium slash

For:

- repeated non-participation
- policy violations
- incompatible source policy claims
- unsupported proof mode claims

Formula:

```text
MediumSlash_i(q)
  = λ2 * SlashableStake_i
```

where `λ2` may be 1% to 5%.

## 13.4 Heavy slash

For:

- fraudulent source proof
- provably deceptive result submission
- fake attestation
- malicious challenge response
- forged phase III proof commitment

Formula:

```text
HeavySlash_i(q)
  = λ3 * SlashableStake_i
```

where `λ3` may be 10% to 100%, with jailing or expulsion.

---

## 14. General Penalty Formula

Define indicator variables:

- `NonReveal_i(q)`
- `Late_i(q)`
- `PolicyViolation_i(q)`
- `Fraud_i(q)`
- `ProofFraud_i(q)`

Then:

```text
Penalty_i(q)
  = NonReveal_i(q)      * LightSlash_i(q)
  + Late_i(q)           * LightSlash_i(q)
  + PolicyViolation_i(q)* MediumSlash_i(q)
  + Fraud_i(q)          * HeavySlash_i(q)
  + ProofFraud_i(q)     * HeavySlash_i(q)
```

Optionally, repeated offenses can escalate punishment:

```text
EscalationMultiplier_i
  = 1 + γ * RecentSlashCount_i
```

Then:

```text
Penalty_i'(q)
  = Penalty_i(q) * EscalationMultiplier_i
```

---

## 15. Challenge Economics

Challengers are crucial because they defend the system when consensus is wrong or manipulated.

## 15.1 Challenge bond

A challenger must post:

```text
ChallengeBond(c, q)
```

This prevents spam.

## 15.2 Successful challenge reward

If the challenge succeeds:

```text
ChallengeReward_c(q)
  = ChallengeReserve(q)
  + κ * SlashedAmount_target(q)
```

where:

- `κ` is the challenger share of slashed funds
- remaining slashed funds may go to treasury, insurance reserve, or burned

## 15.3 Failed challenge penalty

If the challenge fails:

```text
ChallengePenalty_c(q)
  = μ * ChallengeBond(c, q)
```

where `μ` may be full or partial bond forfeiture.

This ensures challenge spam is costly.

---

## 16. Slashed Funds Allocation

Define total slashed amount:

```text
TotalSlashed(q) = Σ Penalty_i'(q)
```

Allocation formula:

```text
ToChallengers(q) = ρ1 * TotalSlashed(q)
ToTreasury(q)    = ρ2 * TotalSlashed(q)
ToBurn(q)        = ρ3 * TotalSlashed(q)
ToInsurance(q)   = ρ4 * TotalSlashed(q)
```

with:

```text
ρ1 + ρ2 + ρ3 + ρ4 = 1
```

Recommended early-stage policy:

- meaningful challenger share
- moderate treasury share
- optional small burn
- optional insurance reserve

---

## 17. Proof Provider Incentives

Phase III proof systems may be too expensive if not separately compensated.

## 17.1 Proof premium budget

Each proof-requiring query should define:

```text
ProofPremium(q)
```

## 17.2 Proof reward formula

If multiple proof providers contribute:

```text
ProofReward_i(q)
  = ProofPremium(q) * ProofQualityWeight_i(q) / Σ ProofQualityWeight_j(q)
```

Where `ProofQualityWeight` can depend on:

- first valid proof
- cheapest accepted proof
- fastest accepted proof
- proof mode priority

Example first-valid policy:

```text
ProofQualityWeight_i(q)
  = 1 if i submitted first valid proof, else 0
```

---

## 18. Bootstrap Plan

The GTOS team does not need to run all oracle agents forever, but should plan for bootstrap.

## 18.1 Phase 0 — internal bootstrap

GTOS team or trusted partners run a small set of bootstrap operators:

- news / event reporter
- official-stat reporter
- scalar normalizer
- dispute bot
- challenge bot

Goal:

- guarantee liveness
- test the protocol
- validate economics
- seed reputation history

## 18.2 Phase 1 — open operator entry

Open registration to external operators with:

- minimum stake
- capability declarations
- transparent commission
- visible performance metrics

## 18.3 Phase 2 — delegation market

Allow delegators to fund the best operators.  
This reduces the need for GTOS to self-finance operator capacity.

## 18.4 Phase 3 — treasury withdrawal

As user-paid coverage rises, GTOS treasury reduces subsidy and stops acting as dominant operator.

---

## 19. Why the GTOS Team Should Not Run Everything Forever

If GTOS runs all oracle agents forever, the system is functionally a centralized data service with on-chain packaging.

That has three drawbacks:

1. weak credibility for market resolution
2. limited capacity and query diversity
3. no real operator economy

The correct long-term role of GTOS is:

- define rules
- maintain protocol
- optionally subsidize strategic categories
- optionally run a minority bootstrap set
- let external operators compete for demand

---

## 20. Participation Decision Model for Operators

An operator will join if the following holds:

```text
Join_i(q) if
  E[TotalReward_i(q)]
  - E[Penalty_i'(q)]
  - OpCost(i,q)
  - DataCost(i,q)
  - ModelCost(i,q)
  - ProofCost(i,q)
  - CapitalCost(i)
  > 0
```

This formula should guide parameter choices.

If too few operators join, increase one or more of:

- query reward
- treasury subsidy
- proof premium
- delegation support

If too many low-quality operators flood the system, increase one or more of:

- minimum stake
- challenge bond
- slashing severity
- policy strictness

---

## 21. Suggested Protocol Parameters

```text
OracleMinSelfStake
OracleMinTotalStake
OracleMaxCommission
OracleLightSlashRate
OracleMediumSlashRate
OracleHeavySlashRate
OracleChallengeBondMin
OracleChallengeReserveRatio
OracleTreasurySubsidyBase
OracleProofPremiumBase
OracleReputationAlpha
OracleEscalationGamma
OracleStakeCapPerRound
```

These can later be added alongside other GTOS protocol constants, which already include native stake and reward-related parameters such as `AgentMinStake` and `DPoSBlockReward` fileciteturn23file0L39-L45.

---

## 22. Recommended Initial Values

A conservative starting point could be:

- `OracleMinSelfStake = 1x AgentMinStake`
- `OracleMaxCommission = 20%`
- `OracleLightSlashRate = 0.5%`
- `OracleMediumSlashRate = 3%`
- `OracleHeavySlashRate = 25%`
- `OracleReputationAlpha = 0.2`
- `OracleStakeCapPerRound = moderate cap to avoid concentration`

These should be tuned through simulation.

---

## 23. Example Reward Calculation

Suppose:

- `QueryRewardPool = 1,000 TOS`
- `ProtocolSubsidy = 200 TOS`
- `ProofPremium = 300 TOS`
- Base pool = `1,200 TOS`

Three accepted operators:

- A: effective reward weight `60`
- B: effective reward weight `30`
- C: effective reward weight `10`

Then:

```text
TotalRewardWeight = 100
```

Base rewards:

```text
A = 1,200 * 60 / 100 = 720
B = 1,200 * 30 / 100 = 360
C = 1,200 * 10 / 100 = 120
```

If A also submits the first valid proof and wins full proof premium:

```text
A total = 720 + 300 = 1,020 TOS
B total = 360
C total = 120
```

If B committed but failed to reveal and receives a 3% medium slash on 2,000 staked TOS:

```text
Penalty_B = 60 TOS
Net_B = 360 - 60 = 300 TOS
```

---

## 24. Example Delegation Calculation

Suppose operator A has:

- `SelfStake = 1,000`
- `DelegatedStake = 4,000`
- `EffectiveStake = 5,000`
- `Commission = 10%`
- `NetOperatorReward = 1,000 TOS`

Then:

```text
DelegatorPool = 1,000 * 4,000 / 5,000 = 800
OperatorPool  = 200
CommissionTake = 10% * 800 = 80
DelegatorNetPool = 720
OperatorFinalReward = 200 + 80 = 280
```

A delegator with 1,000 of the 4,000 delegated stake receives:

```text
DelegatorReward = 720 * 1,000 / 4,000 = 180 TOS
```

---

## 25. Strategic Guidance for GTOS

For GTOS specifically, the best rollout path is:

### Stage A
Use treasury subsidy and bootstrap operators to make the network live.

### Stage B
Focus on a small number of high-value oracle classes:

- binary event markets
- scalar official-stat markets
- enum winner markets
- invalid/dispute resolution markets

### Stage C
Open operator registration, public commission schedules, and delegation.

### Stage D
Reduce treasury share as market-paid coverage grows.

### Stage E
Use Phase III proof modes only where the added assurance justifies the added cost.

---

## 26. Conclusion

A GTOS oracle network will not attract operators merely because OracleHub exists.  
It will attract operators only if the economic system is credible.

That requires:

1. clear demand-side payment
2. positive expected profit for good operators
3. strong penalties for bad operators
4. rational challenger rewards
5. scalable delegation economics
6. explicit bootstrap subsidy and sunset rules

The GTOS team may run early bootstrap agents, but the long-term objective is a self-sustaining market of independent operators, delegators, challengers, and proof providers.

That is how OracleHub becomes not just a protocol module, but a real economic network.
