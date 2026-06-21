# Changelog

## Version 4.0.0

- Process file globs in a sorted order (#291)
- Use new performance metric for server generation time (#260)
- Support for AWS Application and Elastic Load Balancer log formats (#280)
- Always disable queued tracking when sending requests from log import (#274)
- added support for Python 3.5 and above (#267)
- dropped support for Python 2.x (#267)

 
## Unreleased
- Extended `--enable-bots` to accept a Custom Dimension ID (`--enable-bots=N`),
  storing classified bot names in the dimension instead of deprecated Custom Variables.
  Non-bot visits receive 'Not a Bot'. Recommended for Matomo 5+. (#394)
- Added AI/LLM crawlers (GPTBot, ClaudeBot, PerplexityBot, etc.) to bot exclusion list.
