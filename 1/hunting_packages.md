# Hunting on not so popular NPM packages

## Good Articles and starting point

- Resources to follow: https://hackerone.com/nodejs-ecosystem/hacktivity (now discontinued, but good place to learn)
- More latest vulns: https://security.snyk.io/vuln/npm
- [Tweets on latest CVEs](https://twitter.com/CVEnew)

1. [[pac-resolver] NPM package with 3 million weekly downloads had a severe vulnerability](https://httptoolkit.com/blog/npm-pac-proxy-agent-vulnerability/)
2. [[gity] RCE via insecure command formatting](https://hackerone.com/reports/730111) Sadly the package no longer exists.
3. [[wireguard-wrapper] Command Injection via insecure command concatenation](https://hackerone.com/reports/858674)
   - Task on this look for functions which are using exec `const {exec} = require('child_process');` something like this in the code, and not sanitizing the input.
4. [[follow-redirects] Improper Input Validation > 1.15.4](https://security.snyk.io/vuln/SNYK-JS-FOLLOWREDIRECTS-6141137)
   - Task, check which packages are using these vuln(s) and find ways to exploit them
5.

## Testing gained knowledge in the wild (or atleast was my original idea)

Picking up a target on NPM. It needs to meet some basic criteria for a novice like me to find issues with it.

- it should be new and in JS/TS
- it should have at least 100 downloads and more
- it should be still in active development (or I know the dev)

We can use a resource like this Gist which keeps track of all [1000 most popular npm dependencies ](https://gist.github.com/anvaka/8e8fa57c7ee1350e3491). [Snyk Database to see past vulnerabilities.](https://snyk.io/advisor/npm-package/)

Lets start with the package named [fresh](https://www.npmjs.com/package/fresh)

## [Code Audit of Fresh](https://www.npmjs.com/package/fresh)

Putting on the song named [Can't See You](https://www.youtube.com/watch?v=0P3sHqiam5A&list=LL&index=166) because it sounded like the first word is "fresh".

Number of Downloads: ~26M downloads/week.

[Snyk VUlN description](https://security.snyk.io/package/npm/fresh/0.5.1) in 2017.

Also, this package has no dependents which makes it little more interesting. The improvement of token parsing is very nice. I think this was done in a direct response to the DOS vulnerability.

```
Regular Expression Denial of Service (ReDoS)
fresh is HTTP response freshness testing
Affected versions of this package are vulnerable to Regular expression Denial of Service (ReDoS) attacks. A Regular Expression (/ *, */) was used for parsing HTTP headers and take about 2 seconds matching time for 50k characters.
How to fix Regular Expression Denial of Service (ReDoS)?

Upgrade fresh to version 0.5.2 or higher.
```

So, for a 50K character the library would take 2 seconds, because it is inefficient. Which explains why the author[ in the commit changed it to the parseToken](https://github.com/jshttp/fresh/commit/21a0f0c2a5f447e0d40bc16be0c23fa98a7b46ec)

```git
- /**
- * Simple expression to split token list.
- * @private
- */
-
- var TOKEN_LIST_REGEXP = / *, */
- var matches = noneMatch.split(TOKEN_LIST_REGEXP)
+ var matches = parseTokenList(noneMatch)

# followed by the parseTokenList function
```

Package put plainly isn't doing much and the max it does is parse the date. If the date is of the type number it returns true or false. Unless there is a flaw with `Date.parse` the library is good.

Let's see if any popular packages are using `fresh` outdated version and we can exploit them. A query like this in GitHub search [`"fresh": "0.5.0" path:**/*/package.json`](https://github.com/search?q=%22fresh%22%3A+%220.5.0%22+path%3A**%2F*%2Fpackage.json&type=code) provides us with a bunch of results.

## [Code Audit of normalize-url](https://www.npmjs.com/package/normalize-url?activeTab=readme)

Weekly downloads: 26M downloads/week
[Source Code](https://github.com/sindresorhus/normalize-url#readme)
[Snyk-advisory](https://snyk.io/advisor/npm-package/normalize-url)

Version `>=6.0.0 <6.0.1` vulnerable to ReDos. Trying to see if I can do it as well.
[The PR which](https://github.com/sindresorhus/normalize-url/commit/b1fdb5120b6d27a88400d8800e67ff5a22bd2103) fixed the vulnerability.

```git
- const match = /^data:(?<type>._?),(?<data>._?)(?:#(?<hash>.\*))?$/.exec(urlString);
+ const match = /^data:(?<type>[^,]*?),(?<data>[^#]*?)(?:#(?<hash>.*))?$/.exec(urlString);
```

Good test case written by the dev to check for this vuln in the code. Check the PR mentioned.

## [Code Audit of follow-redirects](https://www.npmjs.com/package/follow-redirects?activeTab=readme)

Weekly downloads: 38M
[Source code](https://github.com/follow-redirects/follow-redirects)
[Snyk Advisory](https://security.snyk.io/package/npm/follow-redirects)

Given the number of issues that have been on information exposure and input validation, let's test the package on some real world example scenarios.

> You can mark any request header as sensitive, but the following are treated as sensitive by Edge Diagnostics by default:
>
> - Authorization
> - All headers containing API-Key
> - Proxy-Authorization
> - x-amz-security-token
>   [source](https://techdocs.akamai.com/edge-diagnostics/reference/sensitive-headers)

- [x] Maximum number of redirects [here is the code to check that](https://github.com/follow-redirects/follow-redirects/blob/35a517c5861d79dc8bff7db8626013d20b711b06/index.js#L410-L411). If fairly simple and logic seems airtight

- [x] Should it be however sending CSRF tokens? Raised it [here](https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-69q4-g9j8-rwp7). The code snippet below ensures that sensitive headers are filtered out.

```js
// https://github.com/follow-redirects/follow-redirects/blob/main/index.js#L464
removeMatchingHeaders(/^(?:authorization|cookie)$/i, this._options.headers)
```

## [Code Audit of wireguard-rest](https://www.npmjs.com/package/wireguard-rest)

Weekly download: 0
No Snyk advisory

Sadly, this package was never updated and has [[wireguard-wrapper] One with command Injection via insecure command concatenation](https://hackerone.com/reports/858674) vulnerability and hence is susceptible to the same problem.

[Loom video going over the POC](https://www.loom.com/share/a7048a719de54978b291f3c4bf7c047c). This would enable a direct remote code execution on the device running this package.

```bash
# get request payload
GET http://localhost:1234/wg/showconf/%3Btouch%20%7E%2FDesktop%2Ftype-script-learnings%2Fsecurity%2Fhacked.txt
```

Code to run the server (as provided in the docs)

```js
// run the server
const app = require("wireguard-rest")

app.listen(1234, function () {
  console.log(`Wireguard API listening on port 1234`)
})
```

How was this identified? Looked at the dependents of the original package, and then what version were using the vulnerable package (something which Snyk, and other packages automated)

Didn't see a lot of packages using wireguard-rest, reported to the author irrespective. and requested a CVE from Snyk. GIST: https://gist.github.com/realArcherL/d2a2610c93bef820ddb68198fd48fd4f

## [Code Audit of osenv](https://www.npmjs.com/package/wireguard-rest)

Weekly download: 3M (even though deprecated)

Code read showed that they also use `const {exec} = require('child_process');` in the memo function.

```js
// https://github.com/npm/osenv/blob/master/osenv.js#L11
function memo(key, lookup, fallback) {
  var fell = false
  var falling = false
  exports[key] = function (cb) {
    var val = lookup()
    if (!val && !fell && !falling && fallback) {
      fell = true
      falling = true
      exec(fallback, function (er, output, stderr) {
        falling = false
        if (er) return // oh well, we tried
        val = output.trim()
      })
    }
    exports[key] = function (cb) {
      if (cb) process.nextTick(cb.bind(null, null, val))
      return val
    }
    if (cb && !falling) process.nextTick(cb.bind(null, null, val))
    return val
  }
}
```

Luckily, `fallback` param value is something which is controlled by the code, and cannot be controlled by the user. Hence, this doesn't introduce any security issue.

```js
memo(
  "user",
  function () {
    return isWindows
      ? process.env.USERDOMAIN + "\\" + process.env.USERNAME
      : process.env.USER
  },
  "whoami"
)

// whoami is the fall back command, if this could be controlled by the
// user then something like this would have made it vulnerable:

// Simulate user input
const userInput = "touch hacked.txt" // Dangerous input

// Create a memoized function
memo("user_controlled_function", () => null, userInput)
```

This would execute the user command and we would have a RCE. SUCH IS NOT the case luckily :)

## [Code Audit of @jmondi/url-to-png](https://www.npmjs.com/package/@jmondi/url-to-png)

Weekly download: 5

This package is old but very useful to hackers, if used correctly.
Recently an issue was discovered in the package which [allowed users to read any file arbitrarily](https://github.com/jasonraimondi/url-to-png/issues/47).

The [package has an `ALLOW_LIST`](https://jasonraimondi.github.io/url-to-png/config/#allow-list) where the host can define which services the user is allowed to take screenshots of. By default, it is allowed to take screenshots of services running on localhost or 127.0.0.1 or the IPv6 version of the webpage.

I believe the package should also have a blacklist because of a possible vulnerability. If someone hosts this on a server, users can then take screenshots of the other web services running locally. (this all hinges on the fact that people can use this package to provide screenshot as a service)

Made a comment on the official bug here: https://github.com/jasonraimondi/url-to-png/issues/47#issuecomment-2219577236 (now deleted)

Submitted it as an advisory [here](https://github.com/jasonraimondi/url-to-png/security/advisories/GHSA-342q-2mc2-5gmp.). Even though author accepted it, this isn't a bug. Resolution can be blocked at network level. Added the ability for block list. More improvements can be made on it TBH. [CVE-2024-39919](https://nvd.nist.gov/vuln/detail/CVE-2024-39919)

While working on it, however I found an almost path traversal bug. More on it [here](https://github.com/jasonraimondi/url-to-png/security/advisories/GHSA-vvmv-wrvp-9gjr). [CVE-2024-39918](https://nvd.nist.gov/vuln/detail/CVE-2024-39918)

#### Too Challenging

1. [pretty-error](https://security.snyk.io/package/npm/sanitize-html): has potential for vulns, is in constant development.

### Potential Candidates

1. [@jmondi/url-to-png](https://www.npmjs.com/package/@jmondi/url-to-png)
