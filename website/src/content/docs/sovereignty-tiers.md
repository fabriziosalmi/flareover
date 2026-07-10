---
title: Sovereignty tiers
description: "flareover moves you toward EU-sovereign infrastructure, not merely EU residency, and refuses to let a US-operated region pass as sovereign. The catalogue is generated from the tool's own provider registry."
---

flareover exists to move you toward EU-**sovereign** infrastructure, not merely EU *residency*. Those are different things, and the tool is deliberate about the difference. Every provider it offers is tagged, and it will never let a US-operated option pass as sovereign.

```bash
flareover providers   # lists every edge provider with its tier
```

:::note[Generated from the code]
The catalogue below is generated from flareover's own `provider.Registry`: the same list `flareover providers` prints and `--edge-provider` validates against. A test fails if this page drifts from it, so the tiers can't be quietly rewritten.
:::

## The two tiers

| Tier | What it means |
|------|---------------|
| **EU-owned (sovereign)** | An EU-headquartered operator with **no non-EU parent** that could be compelled to hand over data. EU jurisdiction only. |
| **US-operator · EU-region** | A US company's EU datacenter. Your data *resides* in the EU, but the operator is under **US CLOUD Act / FISA** reach. Offered as a pragmatic bridge, **never** labelled sovereign, always with a nudge to the EU-owned options. |

The distinction matters because CLOUD Act reach follows the *operator's* nationality, not the datacenter's location. "It's in Frankfurt" does not make it sovereign if the company holding the keys answers to a foreign subpoena.

## Edge provider catalogue

Use a key with `flareover prepare --edge-provider <key>` to emit a cloud-init that boots a Caddy edge on that provider.

### EU-owned (sovereign)

| Key | Provider | Where it sits | Jurisdiction |
|-----|----------|---------------|--------------|
| `hetzner` | Hetzner | DE (Nuremberg/Falkenstein) · FI (Helsinki) | EU jurisdiction only |
| `ovh` | OVHcloud | FR (Gravelines/Roubaix) + EU | EU jurisdiction only |
| `contabo` | Contabo | DE (Munich) + EU | EU jurisdiction only |
| `aruba` | Aruba | IT (Arezzo/Milan) | EU jurisdiction only · Italian operator |
| `scaleway` | Scaleway | FR (Paris) · NL · PL | EU jurisdiction only |
| `leaseweb` | Leaseweb | NL (Amsterdam) + EU | EU jurisdiction only · Dutch operator |

### US-operator · EU-region (residency only, **not** sovereign)

| Key | Provider | Where it sits | The honest catch |
|-----|----------|---------------|------------------|
| `aws-milano` | AWS (eu-south-1, Milan) | IT (Milan) | EU residency, but US CLOUD Act / FISA reach |
| `gcp-milano` | Google Cloud (europe-west8, Milan) | IT (Milan) | EU residency, but US CLOUD Act / FISA reach |
| `azure-milano` | Azure (Italy North, Milan) | IT (Milan) | EU residency, but US CLOUD Act / FISA reach |

## How tiering shows up across the tool

The same honesty applies wherever a US-operated option appears:

- **[DNS targets](/docs/dns-targets/):** `route53`, `clouddns`, and `azure` are labelled US-operated; provisioning against them prints a nudge to the EU-owned options.
- **[Object storage](/docs/object-storage/):** the managed destinations are all EU-owned and EU-region-scoped.
- **Edge:** `flareover providers` groups the two tiers explicitly.

> This is corporate-jurisdiction information to inform a choice, **not legal advice**. Your obligations depend on your data and your regulators; confirm the exact region and terms with the provider at deploy time.

## Why sovereignty at all

The whole point of leaving a large managed edge is usually some mix of cost, lock-in, and control. If you're doing the work anyway, flareover makes it easy to land somewhere genuinely under EU jurisdiction, and refuses to let "EU region" quietly stand in for "EU sovereign", which is exactly the kind of silent substitution the [contract](/docs/the-contract/) is built to prevent.
