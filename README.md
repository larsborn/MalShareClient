# MalShare API Client
Python-based Client for the [malshare.com] service.

## Installation

Requires at least Python 3.7 and the package `requests` to be installed. Fully compatible with being run in a virtual
environment. It is recommended to set the environment variable `MALSHARE_API_KEY` to the API key you received via email
after registering at https://malshare.com/register.php.

## Example Usage
After aliasing the script `malshare.py` to `mals` and setting the environment variable `MALSHARE_API_KEY` a typical
session may look like the following:

```Batch
> mals download --file-name Mozy.elf fd9c3d3cb300d855db3da4bf3ad9760b4875a400d9a99053245cb296c56849b6
[INFO] Downloaded 95268 bytes.

> upx -d Mozy.elf
[...]
Unpacked 1 file.

> mals upload Mozy.elf
[INFO] Successfully uploaded "Mozy.elf" (SHA256: 83441d77abb6cf328e77e372dc17c607fb9c4a261722ae80d83708ae3865053d).
```





[malshare.com]: https://www.malshare.com/
