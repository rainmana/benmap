# Statistical method

## Purpose

Benmap measures whether an eligible population's leading decimal digits differ from
Benford's theoretical distribution. It also reports ordinary distribution features
that do not depend on Benford's law.

The result is a diagnostic for ranking and investigation. It is not a classifier of
hosts, users, software, or intent.

## First-digit distribution

For leading digit \(d \in \{1, \ldots, 9\}\), Benford's law predicts:

\[
P(D=d)=\log_{10}\left(1+\frac{1}{d}\right)
\]

For every positive finite observation, Benmap extracts the first significant
base-10 digit. Zero, negative, missing, and non-finite values are excluded and
reported.

## Eligibility gate

Benmap does not assume every numeric field is a Benford population. The default gate
requires all of the following:

- 200 positive, complete samples.
- An expected count of at least five for every digit. Because digit 9 has the lowest
  expected probability, this imposes an independent floor of approximately 110
  samples if the configured sample minimum is reduced.
- A maximum-to-minimum ratio spanning at least two decimal orders of magnitude.
- At least nine distinct values.
- A unique-value ratio of at least 0.05.

A failed gate yields `eligible = false`, concrete reasons, and no MAD,
Jensen-Shannon, or chi-square value. Benmap still reports the numeric span, unique
ratio, duplicate ratio, dominant value, and dominant share.

These defaults are operational guardrails, not universal mathematical theorems.
Future cohort-specific policies can override them when supported by validation data.

## Mean absolute deviation

For observed digit proportion \(\hat{p}_d\) and expected Benford proportion \(b_d\):

\[
MAD = \frac{1}{9}\sum_{d=1}^{9}|\hat{p}_d-b_d|
\]

MAD is an effect-size description. Benmap does not attach universal labels such as
“acceptable,” “suspicious,” or “fraudulent” because thresholds are domain- and
population-dependent.

## Jensen-Shannon divergence

Benmap calculates base-2 Jensen-Shannon divergence between the observed and Benford
probability vectors:

\[
JSD(P\|B)=\frac{1}{2}D_{KL}(P\|M)+\frac{1}{2}D_{KL}(B\|M)
\]

where \(M=(P+B)/2\). This symmetric, finite measure is bounded between zero and one
when base-2 logarithms are used.

## Pearson chi-square statistic

For observed count \(O_d\) and expected count \(E_d=n b_d\):

\[
\chi^2=\sum_{d=1}^{9}\frac{(O_d-E_d)^2}{E_d}
\]

The first-digit test has eight degrees of freedom. The MVP reports the statistic but
does not turn it into an automated verdict. With large samples, statistically
significant differences can be operationally trivial.

## Scale-sensitivity diagnostic

A genuine Benford distribution is scale invariant. The Python analyzer multiplies
the eligible population by several positive constants and records the range of the
resulting MAD values. A large range warns that the empirical result depends strongly
on unit choice.

This diagnostic is reported separately and is not yet a hard eligibility gate.

## Cohorting

The current HTTP NSE summary analyzes each feature across the scan. The offline
roadmap adds explicit cohorts such as:

```text
measurement type
+ application protocol
+ TLS/plaintext
+ request method and normalized path
+ service or responder class
```

Unrelated measurement types must never be pooled merely to create a broad numeric
range. A mixed population can manufacture apparent conformance while representing
nothing coherent.

## Interpretation

A high deviation score can arise from:

- A shared reverse proxy or WAF response.
- Rate limiting or a fixed access-denied page.
- A homogeneous application deployment.
- A synthetic responder, honeypot, or sinkhole.
- Measurement clipping or capture truncation.
- A population that only barely passed an imperfect eligibility policy.
- Ordinary environmental change.

None of those explanations is automatically malicious. The next analytical step is
contributor localization and comparison against the environment's own baseline.
