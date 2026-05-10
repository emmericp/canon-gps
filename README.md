# Canon GPS Tracker Log Importer

Script to import GPS traces from Canon GP-E2 GPS Trackers without using Canon software.


# Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

## Import traces

```bash
python canon_gps_reader.py import [--format gpx|csv] [--output-dir .] [--overwrite]
```

That's it!
All flags are optional, by default it will import traces in GPX format into the current dir, skipping already existing entries.

Permission error? Try `sudo`.

## Configure log interval

```bash
python canon_gps_reader.py config get interval
python canon_gps_reader.py config set interval <time in seconds>
```

## Random notes

* Parser is untested on "negative" coordinates, if you have a trace on the southern hemisphere or west of London: please run it with `--format csv --debug` and file an issue
* There are still some mystery bytes in there, see code. One of them might be the compass which would be nice to have
* Untested on any other Firmware than 2.0.2 which is the latest as of 2026
* Since older cameras communicate via USB with it, there has to be some live mode, but that would be annoying to trace
* Scanned the whole config address space, looks like interval is the only configurable setting, see [debug/scan_properties.py](debug/scan_properties.py)