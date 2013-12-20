#This is fork from hapi travelogue.js to return error object instead of doing redirection
# https://github.com/spumko/travelogue/issues/30
Passport = require("passport")
Hapi = null
internals = {}
internals.defaults =
  urls:
    failureRedirect: "/login"
    successRedirect: "/"

  excludePaths: []

exports.register = (plugin, options, next) ->
  internals.setHapi plugin.hapi
  settings = plugin.hapi.utils.applyToDefaults(internals.defaults, options)
  plugin.dependency "yar"
  plugin.api "settings", settings
  plugin.api "passport", Passport
  Passport.framework
    initialize: internals.initialize
    authenticate: internals.authenticate(settings)

  plugin.ext "onPreAuth", [ Passport.initialize(), internals.exclude(settings.excludePaths, Passport.session()) ],
    after: "yar"

  plugin.auth "passport",
    implementation: new internals.Scheme(settings, plugin.hapi)
    defaultMode: settings.defaultMode

  next()

internals.exclude = (paths, callback) ->
  (request, next) ->
    isExcludable = false
    complete = ->
      if isExcludable
        next()
      else
        callback request, next

    paths.forEach (path) ->
      isExcludable = true  if request.url.path.indexOf(path) >= 0

    complete()

internals.initialize = ->
  (request, next) ->
    passport = this
    request._passport = {}
    request._passport.instance = passport
    passportSession = request.session
    if passportSession
      request._passport.session = request.session
    else
      request.session = request.session or {}
      passportSession = {}
      request.session["_passport"] = passportSession
      request._passport.session = passportSession
    request.session.lazy true  if request.session.hasOwnProperty("lazy")
    request.session._isAuthenticated = ->
      property = "user"
      property = request._passport.instance._userProperty  if request._passport and request._passport.instance._userProperty
      (if (request[property]) then true else false)

    request.session._login = request.session._logIn = (user, options, done) ->
      throw new Error("passport.initialize() middleware not in use")  unless request._passport
      if not done and typeof options is "function"
        done = options
        options = {}
      options = options or {}
      property = request._passport.instance._userProperty or "user"
      session = request.session or null
      request[property] = user
      if session and request._passport.instance.serializeUser
        request._passport.instance.serializeUser user, (err, obj) ->
          if err
            request[property] = null
            return done(err)
          request._passport.session.user = obj
          request.session.user = obj
          done()
      else
        done and done()

    request.session._logout = request.session._logOut = ->
      throw new Error("passport.initialize() middleware not in use")  unless request._passport
      property = request._passport.instance._userProperty or "user"
      request[property] = null
      delete request._passport.session.user

    next()

internals.authenticate = (settings) ->
  (name, options, callback) ->
    self = this
    if not callback and typeof options is "function"
      callback = options
      options = {}
    options = options or {}
    name = [ name ]  unless Array.isArray(name)
    authenticate = (request, next) ->
      passport = this
      failures = []
      unless next
        next = (err) ->
          request.reply.redirect (if err then (options.failureRedirect or settings.failureRedirect or "/") else (options.successRedirect or settings.successRedirect or "/"))
      allFailed = internals.allFailedFactory(request, failures, options, callback)
      attempt = internals.attemptFactory(passport, request, name, failures, allFailed, options, next, callback)
      attempt 0, next

internals.allFailedFactory = (request, failures, options, callback) ->
  allFailed = ->
    if callback
      if failures.length is 1
        return callback(null, false, failures[0].challenge, failures[0].status)
      else
        challenges = failures.map((f) ->
          f.challenge
        )
        statuses = failures.map((f) ->
          f.status
        )
        return callback(null, false, challenges, statuses)
    failure = failures[0] or {}
    challenge = failure.challenge or {}
    if options.failureFlash
      flash = options.failureFlash
      if typeof flash is "string"
        flash =
          type: "error"
          message: flash
      flash.type = flash.type or "error"
      type = flash.type or challenge.type or "error"
      msg = flash.message or challenge.message or challenge
      request.session.flash type, msg  if typeof msg is "string"
    if options.failureMessage
      msg = options.failureMessage
      msg = challenge.message or challenge  if typeof msg is "boolean"
      if typeof msg is "string"
        request.session.messages = request.session.messages or []
        request.session.messages.push msg
    return request.reply.redirect(options.failureRedirect)  if options.failureRedirect
    rchallenge = []
    rstatus = null
    i = 0
    l = failures.length

    while i < l
      failure = failures[i]
      challenge = failure.challenge or {}
      status = failure.status
      if typeof challenge is "number"
        status = challenge
        challenge = null
      rstatus = rstatus or status
      rchallenge.push challenge  if typeof challenge is "string"
      ++i
    request.reply Hapi.error.unauthorized("Unauthorized", rchallenge or null)

internals.attemptFactory = (passport, request, name, failures, allFailed, options, next, callback) ->
  attempt = (i, cb) ->
    delegate = {}
    options.session = options.session or request.session
    delegate.success = (user, info) ->
      Hapi.utils.applyToDefaults request.session, request._synth.session  if request._synth.session
      return callback(null, user, info)  if callback
      info = info or {}
      if options.successFlash
        flash = options.successFlash
        if typeof flash is "string"
          flash =
            type: "success"
            message: flash
        flash.type = flash.type or "success"
        type = flash.type or info.type or "success"
        msg = flash.message or info.message or info
        request.session.flash type, msg  if typeof msg is "string"
      if options.successMessage
        msg = options.successMessage
        msg = info.message or info  if typeof msg is "boolean"
        if typeof msg is "string"
          request.session.messages = request.session.messages or []
          request.session.messages.push msg
      request[options.assignProperty] = user  if options.assignProperty
      complete = ->
        if options.successReturnToOrRedirect
          url = options.successReturnToOrRedirect
          if request.session and request.session.returnTo
            url = request.session.returnTo
            delete request.session.returnTo
          return request.reply.redirect(url)
        return request.reply.redirect(options.successRedirect)  if options.successRedirect
        cb()

      request.session._logIn user, options, (err) ->
        return cb(err)  if err
        if options.authInfo
          passport.transformAuthInfo info, internals.transformAuthInfoCallback(request, cb, complete)
        else
          complete()

    delegate.fail = (challenge, status) ->
      failures.push
        challenge: challenge
        status: status

      attempt i + 1, cb

    delegate.pass = ->
      if request._synth.user
        request.user = request._synth.user
        request.session.user = request.user
      cb()

    delegate.error = internals.delegateErrorFactory(cb)
    delegate.redirect = internals.delegateRedirectFactory(request)
    layer = name[i]
    return allFailed()  unless layer
    prototype = passport._strategy(layer)
    return next(Hapi.error.internal("No strategy registered under the name:" + layer))  unless prototype
    actions = internals.actionsFactory()
    strategy = Object.create(prototype)
    for method of actions
      strategy[method] = actions[method].bind(delegate)
    req = {}
    req.query = request.url.query
    req.body = request.payload
    req._passport = request._passport
    req.session = request.session
    request._synth = req
    req.url = request.url
    req.url.method = request.method.toUpperCase()
    req.url.url = request.url.href
    strategy.authenticate req, options

internals.actionsFactory = ->
  success: (user, info) ->
    @success.apply this, arguments

  fail: (challenge, status) ->
    @fail.apply this, arguments

  redirect: (url, status) ->
    @redirect.apply this, arguments

  pass: ->
    @pass.apply this, arguments

  error: (err) ->
    @error.apply this, arguments

internals.transformAuthInfoCallback = (request, cb, complete) ->
  (err, tinfo) ->
    return cb(err)  if err
    request.authInfo = tinfo
    complete()

internals.delegateErrorFactory = (cb) ->
  (err) ->
    err = Hapi.error.internal("Passport Error: " + err)  if err
    cb err

internals.delegateRedirectFactory = (request) ->
  (url, status) ->
    request.reply.redirect url

internals.Scheme = (options, hapi) ->
  @settings = options
  @hapi = hapi
  this

internals.Scheme::authenticate = (request, callback) ->
  return callback(null, {})  if request.session._isAuthenticated()
  #VLi patch added here
  errReply = err: "unauthenticated"
  callback new @hapi.response.Obj(errReply).code(401)
  #VLi patch end here

internals.setHapi = (module) ->
  Hapi = Hapi or module

exports.internals = internals  if process.env.NODE_ENV is "test"
