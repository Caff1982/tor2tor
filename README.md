```
 __               ______ __
|  |_.-----.----.|__    |  |_.-----.----.
|   _|  _  |   _||    __|   _|  _  |   _|
|____|_____|__|  |______|____|_____|__|
```

**tor2tor** scrapes a given onion link and captures screenshots of all links available on it.

[![Docker](https://github.com/rly0nheart/tor2tor/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/rly0nheart/tor2tor/actions/workflows/docker-publish.yml)
[![CodeQL](https://github.com/rly0nheart/tor2tor/actions/workflows/codeql.yml/badge.svg)](https://github.com/rly0nheart/tor2tor/actions/workflows/codeql.yml)
![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
# Installation ⬇️
## Note ⚠️
> This assumes the Firefox browser is installed on the user's machine.

<details>
  <summary>🐧 GNU/Linux</summary>
  
  **1.** Clone the repository
  ```commandline
  git clone https://github.com/rly0nheart/tor2tor
  ```

  **2.** Move to the tor2tor directory
  ```commandline
  cd tor2tor
  ```
  **3.** Run the installation script
  > Assuming you've already made it executable with `sudo chmod +x install.sh`

  ```commandline
  sudo ./install.sh
  ```
  The installation script will install `tor` then download and setup the latest version of `geckodriver`, and install `tor2tor` together with its dependencies (because we're all too lazy to manually do it)
  ![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
</details>

<details>
  <summary>🪟 Windows</summary>

  ## Note ⚠️
  > This assumes you have docker installed and running

  For Windows users, you can just pull the docker image from [DockerHub](https://hub.docker.com/r/rly0nheart/tor2tor) by running:
  ```commandline
  docker pull rly0nheart/tor2tor
  ```
![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
</details>


# Usage ⌨️
<details>
  <summary>🐧 GNU/Linux</summary>
  
  If you installed the program with the `install.sh` script, then you can just run the following command to see available options and some basic usage examples:
  ```commandline
  tor2tor --help
  ```
  or 
  ```commandline
  t2t --help
  ```
Calling it with an onion url should look like this:
```commandline
sudo tor2tor http://example.onion
```

![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

</details>

<details>
  <summary>📦 Docker Container</summary>
  
  You can call the tor2tor container with `docker run`:
  ```commandline
  docker run rly0nheart/tor2tor --help
  ```

  Calling the tor2tor container with an onion url should look like this:
  ```commandline
  docker run --tty --volume $PWD/tor2tor:/root/tor2tor rly0nheart/tor2tor http://example.onion
  ```
## Note ⚠️
  > --tty Allocates a pseudo-TTY, use it to enable the container to display colours on output
  >> --volume $PWD/tor2tor:/root/tor2tor Will mount the tor2tor directory from the container to your host machine.

![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
</details>


# Uninstalling ❌
<details>
  <summary>🐧 GNU/Linux</summary>

  ## Note ⚠️
  > Assuming you also made it executable with `sudo chmod +x uninstall.sh`

  Navigate to the `tor2tor` directory that you cloned and find `uninstall.sh` file.
  
  Run it!
  ```commandline
  sudo ./uninstall.sh
  ```
  This will uninstall `tor`, delete the `geckodriver` binary and uninstall `tor2tor`
  ![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
</details>

<details>
  <summary>📦 Docker Container</summary>

  You can stop (if it's running) and remove the container by running:
  ```commandline
  docker rm -f rly0nheart/tor2tor
  ```
![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
</details>

# Important ⚠️
As you probably already know,Tor routes data via three relays (servers) for your privacy.
As a result, connections become slower than an ordinary connection.

## Point ⚠️
Once you start **Tor2Tor**, give it at least 2 minutes tops to query the specified onion url and extract links from it. 

## CI/CD Workflow 🌊

### Docker Image Building 📦

- Pushing to or merging into the `latest` branch triggers an automatic build of the Docker image.
- This image is tagged as `latest` on Docker Hub, indicating it's the most stable release.

![-](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)
![me](https://github.com/rly0nheart/glyphoji/assets/74001397/e202c4c1-9a69-40c4-a4da-1e95befb08ee)
