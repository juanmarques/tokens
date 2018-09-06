# awful-tokens

## Authtoken Server of Doom

* RESTful services for generating, encryption and validating public keys

### Installation and Configuration

##### Pre-requisite:
Install [NPM] & [NODEJS]

Install and run [Redis] locally or on [Docker].

To run RedisServer in [Docker]:
docker run --name redis -p 6379:6379 -e ALLOW_EMPTY_PASSWORD=yes bitnami/redis:latest

###### To run
Go into your project folder with command line and type :
* node npm install - That will download all the dependencies of the project
* Now you're ready to run `node index.js`. or to run tests `jasmine`.(make sure that you have started redis and it's still running)

#### Technologies

* [NodeJS] - Node.js® is a JavaScript runtime,used to develop the services.
* [NPM]    - npm is the package manager for JavaScript, used to install all the dependencies and manage
* [Redis]  - Redis is an open source (BSD licensed), in-memory data structure store, used as a database.
* [Jasmine]- Jasmine is a behavior-driven development framework for testing JavaScript code, used to unit tests.

### What would be great to have?
* [JWT] to manage the tokens
* [Kubernetes] and [Docker] to have a scalable application with high availability

[//]: #

   [NodeJS]:<https://nodejs.org/en/>
   [NPM]: <https://www.npmjs.com>
   [Redis]: <https://redis.io>
   [Jasmine]: <https://jasmine.github.io>
   [JWT]: <https://jwt.io>
   [kubernetes]:<https://kubernetes.io>
   [Docker]: <https://www.docker.com/>