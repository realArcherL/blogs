# Hunting on not so popular NPM packages

Picking up a target on NPM. It needs to meet some basic criteria for a novice like me to find issues with it.

- it should be new and in JS/TS
- it should have at least 100 downloads and more
- it should be still in active development (or I know the dev)

We can use a resource like this Gist which keeps track of all [1000 most popular npm dependencies ](https://gist.github.com/anvaka/8e8fa57c7ee1350e3491)

Lets start with the package named [fresh](https://www.npmjs.com/package/fresh)

## Code Audit of Fresh

Putting on the song named [Can't See You](https://www.youtube.com/watch?v=0P3sHqiam5A&list=LL&index=166) because it sounded like the first word is "fresh". Also, the package gets like 120M downloads/month.

Also, this package has no dependents which makes it little more interesting. The improvement of token parsing is very nice. I think this was done in a direct response to the DOS vulnerability. [Snyk VUlN description](https://security.snyk.io/package/npm/fresh/0.5.1) in 2017.

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
