# Canon GPS Tracker Log Importer

Script to import GPS traces from Canon GP-E2 GPS Trackers without using Canon software.


# Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Import traces as GPX or CSV:

```bash
sudo python canon_gps_reader.py --format [gpx|csv]
```

That's it! It will import all traces from the device that don't yet exist in `--output-dir` (default: current dir).


## Random notes

* Parser is untested on "negative" coordinates, if you have a trace on the southern hemisphere or west of London: please run it with `--format csv --debug` and file an issue
* There are still some mystery bytes in there, see code. One of them might be the compass which would be nice to have
* Untested on any other Firmware than 2.0.2 which is the latest as of 2026
* It'd be nice to read/write the configuration memory
* Since older cameras communicate via USB with it, there has to be some live mode, but that would be annoying to trace