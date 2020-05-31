# About Grafolean NetFlow bot

This package is a NetFlow bot for Grafolean, an easy to use generic monitoring system.

The architecture of this bot is a bit unusual. The reason is a [Docker issue](https://github.com/moby/libnetwork/issues/1994) which prevents containers from determining the source IP of the NetFlow UDP packets. Because we need this information, we must put a single process outside the Docker network (*collector*), then pass every incoming packet via named pipe to another process inside the network (*writer*), which writes it to the database (PostgreSQL). The fourth process is a bot, waking up at regular intervals and sending aggregated data to Grafolean.

Note that the system holds the not-yet-aggregated data in PostgreSQL, so it might be possible to perform further analysis if any incidents occur in the network. The data is however not in its original form for storage capacity reasons (only the most important of the fields are saved).

Under the hood [python-netflow-v9-softflowd](https://github.com/bitkeks/python-netflow-v9-softflowd) is used. For local testing (NetFlow v5) [nflow-generator](https://github.com/nerdalert/nflow-generator) can be used.

Requirements:
- NetFlow exporters must be able to send data to the port where *collector* is listening (see `NETFLOW_PORT` environment variable description below)
- Grafolean must be accessible via HTTP(S)

Current limitations:
- only NetFlow v9 and v5 are supported

# License

License is Commons Clause license (on top of Apache 2.0) - source is available, you can use it for free (commercially too), modify and
share, but you can't sell it. See [LICENSE.md](https://github.com/grafolean/grafolean-netflow-bot/blob/master/LICENSE.md) for details.

If in doubt, please [open an issue](https://github.com/grafolean/grafolean-netflow-bot/issues) to get further clarification.

# Install

> **IMPORTANT**: these instructions are only useful if you wish to install a *remote* agent / bot. Please see Grafolean installation instructions if you only wish to enable a bot as part of default Grafolean installation.

Requirements: `docker` and `docker-compose`.

1) log in to Grafolean service (either self-hosted or https://grafolean.com/) and create a new `Bot`. Make sure that selected protocol is `NetFlow`. Copy the bot token.

2) save [docker-compose.yml](https://github.com/grafolean/grafolean-netflow-bot/raw/master/docker-compose.yml) to a local file:
    ```
    $ mkdir ~/netflow
    $ cd ~/netflow
    $ curl https://github.com/grafolean/grafolean-netflow-bot/raw/master/docker-compose.yml > docker-compose.yml
    ```

3) save [.env.example](https://raw.githubusercontent.com/grafolean/grafolean-netflow-bot/master/.env.example) to `.env` and edit it:
    ```
    $ curl https://raw.githubusercontent.com/grafolean/grafolean-netflow-bot/master/.env.example > .env
    ```
    - mandatory: `BACKEND_URL` (set to the URL of Grafolean backend, for example `https://grafolean.com/api`),
    - mandatory: `BOT_TOKEN` (set to the bot token from step 1),
    - mandatory: `DB_DIR` (directory to which the database with non-aggregated results is saved),
    - optional: `NETFLOW_PORT` (UDP port on which *collector* listens for incoming packets)
    - optional: `JOBS_REFRESH_INTERVAL` (interval in seconds at which the jobs definitions will be updated)

4) run: `docker-compose up -d`

If you get no error, congratulations! Everything else is done from within the Grafolean UI. You can however check the status of container as usually by running `docker ps` and investigate logs by running `docker-compose logs -f` in the `~/netflow/` directory.

## Upgrade

1) `$ docker-compose pull`
2) `$ docker-compose down`
3) `$ docker-compose up -d`

## Debugging

Container logs can be checked by running:
```
$ docker logs --since 5m -f grafolean-netflow-bot
```

## Building locally

If you wish to build the Docker image locally (for debugging or for development purposes), you can use a custom docker-compose YAML file:
```
docker-compose -f docker-compose.dev.yml build
```

As before, `.env.example` can be copied to `.env` and all settings can be altered there.

## Issues

If you encounter any problems installing or running the software, please let us know in the [issues](https://github.com/grafolean/grafolean-netflow-bot/issues). Please make an effort when describing the issue. If we can reproduce the problem, we can also fix it much faster.

# Development

## Contributing

Please open an issue about the problem you are facing before submitting a pull request.
