# Third-Party Notices

This project incorporates components from the following third-party software.

## falcon-mcp (CrowdStrike)

- Source: https://github.com/CrowdStrike/falcon-mcp
- License: MIT
- Copyright (c) 2024 CrowdStrike Holdings, Inc.

The module `src/crowdstrike_mcp/modules/idp.py` is a port and
adaptation of `falcon_mcp/modules/idp.py` from that project, translated to this
repository's tool-registration, typing, and error-handling conventions. Notable
differences from the upstream version: pydantic `Field` annotations replaced with
`Annotated[Type, "description"]`; `_base_query_api_call` helper replaced with direct
falconpy `graphql()` calls + our `format_api_error`; `_add_tool` signature adapted
to our `tier="read"` pattern; output formatting via `format_text_response(..., raw=True)`.

Full upstream license text:

MIT License

Copyright (c) 2024 CrowdStrike Holdings, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...
