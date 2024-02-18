# template-cli

template-cli is a template project to build a cli with Go.

Clone it with:

```bash
# install gonew
go install golang.org/x/tools/cmd/gonew@latest
# use gonew to create your project based on this template
gonew github.com/sgaunet/template-cli gitplatform.com/username/awesome_new_project
cd awesome_new_project
git init
git add .
git remote add origin git@gitplatform.com:username/awesome_new_project
git push -u origin master
```

# Getting started

Usage is quite simple :

```
$ ./template-cli -h
...
```

# Install

## From binary 

Download the binary in the release section. 

## From Docker image

Docker registry is: 

## Deployment with docker-example

!TODO

## Deployment iwth kubernetes manifests

!TODO

## Deployment with helm

!TODO


# Development

This project is using :

* golang
* [task for development](https://taskfile.dev/#/)
* docker
* [docker buildx](https://github.com/docker/buildx)
* docker manifest
* [goreleaser](https://goreleaser.com/)
* [venom](https://github.com/ovh/venom) : Tests
* [pre-commit](https://pre-commit.com/)

There are hooks executed in the precommit stage. Once the project cloned on your disk, please install pre-commit:

```
brew install pre-commit
```

Install tools:

```
task dev:install-prereq
```

And install the hooks:

```
task dev:install-pre-commit
```

If you like to launch manually the pre-commmit hook:

```
task dev:pre-commit
```


# Tests

Tests are done with [venom](https://github.com/ovh/venom).

```
cd tests
venom run
```

