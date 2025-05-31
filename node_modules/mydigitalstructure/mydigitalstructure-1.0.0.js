var _ = require('lodash')
var moment = require('moment');

module.exports = 
{
	data: {session: undefined},

	init: function (callBack, settings)
			{
				if (settings == undefined)
				{	
					var fs = require('fs');

					fs.readFile('settings.json', function (err, buffer)
					{
						if (!err)
						{	
							var _settings = buffer.toString();
							settings = JSON.parse(_settings);
							module.exports.data._settings = settings;

							if (!_.isUndefined(settings))
							{
								if (!_.isUndefined(settings.mydigitalstructure))
								{
									settings = settings.mydigitalstructure;
								}

								module.exports.data.settings = settings;
							}

							module.exports.logon(callBack, settings)
						}	
					});
				}
				else
				{
					module.exports.data._settings = settings;
							
					if (!_.isUndefined(settings.mydigitalstructure))
					{
						settings = settings.mydigitalstructure;
					}

					module.exports.data.settings = settings;
					module.exports.logon(callBack, settings);
				}	
			},

	logon: 
			function (callBack, settings, param)
			{
				var https = require('https');
				var authenticationLevel = module.exports.data.settings.authenticationLevel;
				if (_.isUndefined(authenticationLevel)) {authenticationLevel = 1};
				var logon = settings.logon;
				var password = settings.password;
				var code = module.exports._util.param.get(param, 'code').value;

				var data = 
				{
					method: 'LOGON',
					logon: logon,
					localtime: moment().format('D MMM YYYY HH:mm:ss')
				}

				var requestData = 'logon=' + logon +
										'&localtime=' + moment().format('D MMM YYYY HH:mm:ss');

				if (authenticationLevel == 1)
				{
					requestData += '&passwordhash=' + module.exports._util.hash(logon + password);
				}
				else if (authenticationLevel == 2)
				{
					requestData += '&passwordhash=' + module.exports._util.hash(logon + password + module.exports.data.session.logonkey)
				}
				else if (authenticationLevel == 3)
				{
					requestData += '&passwordhash=' + module.exports._util.hash(logon + password + module.exports.data.session.logonkey + code)
				}

				module.exports._util.testing.data(requestData, 'mydigitalstructure.logon.request');
				
				var options =
				{
					hostname: settings.hostname,
					port: 443,
					path: '/rpc/logon/?method=LOGON',
					method: 'POST',
					headers:
					{
						'Content-Type': 'application/x-www-form-urlencoded',
						'Content-Length': requestData.length
					}
				};

				module.exports._util.testing.data(options, 'mydigitalstructure.send.request.options');

				var req = https.request(options, function(res)
				{
					res.setEncoding('utf8');

					var data = '';
					
					res.on('data', function(chunk)
					{
					  	data += chunk;
					});
					
					res.on('end', function ()
					{	
						module.exports._util.testing.data(data, 'mydigitalstructure.send.response.end');
						var _data = JSON.parse(data);
				    	module.exports.data.session = _data;
				    	if (_.isFunction(callBack)) {callBack({data: _data, settings: settings})};
					});
				});

				req.on('error', function(error)
				{
					module.exports._util.testing.data(error.message, 'mydigitalstructure.logon.response.error');
				  	if (_.isFunction(callBack)) {callBack({error: error})};
				});

				module.exports._util.testing.data(requestData, 'mydigitalstructure.send.request.data');

				req.write(requestData);
				req.end()
			},

	send: function (options, data, callBack)
			{
				var https = require('https');
				var querystring = require('querystring');
				var settings = module.exports.data.settings;
				var session = module.exports.data.session;
				var requestData;

				if (_.isUndefined(data))
				{
					requestData = options.data
				}
				else
				{
					requestData = data
				}

				if (_.isObject(requestData))
				{
					data.sid = session.sid;
					data.logonkey = session.logonkey;

					requestData = querystring.stringify(requestData);
				}
				else
				{
					if (!_.isUndefined(requestData))
					{	
						requestData = requestData + '&sid=' + session.sid + '&logonkey=' + session.logonkey;
					}
					else
					{
						requestData = 'sid=' + session.sid + '&logonkey=' + session.logonkey;
					}
				}

				if (_.isUndefined(callBack))
				{
					callBack = options.callBack
				}					
						
				if (options.type == undefined) {options.type = 'POST'}
						
				var requestOptions =
				{
					hostname: settings.hostname,
					port: 443,
					path: options.url,
					method: options.type,
					headers:
					{
						'Content-Type': 'application/x-www-form-urlencoded',
						'Content-Length': requestData.length
					}
				};

				module.exports._util.testing.data(options, 'mydigitalstructure.send.request.options');

				var req = https.request(requestOptions, function(res)
				{
					res.setEncoding('utf8');

					var data = '';
					
					res.on('data', function(chunk)
					{
					  	data += chunk;
					});
					
					res.on('end', function ()
					{	
						module.exports._util.testing.data(data, 'mydigitalstructure.send.response.end');
				    	if (_.isFunction(callBack)) {callBack(options, data)};
					});
				});

				req.on('error', function(error)
				{
					module.exports._util.testing.message(error.message, 'mydigitalstructure.send.response.error');
				  	if (callBack) {callBack(options, data, error)};
				});

				module.exports._util.testing.data(requestData, 'mydigitalstructure.send.request.data');

				req.write(requestData);
				req.end()
			},

	_util: 
			{
				testing:
				{
					message: function (message, context)
					{
						var settings = module.exports.data.settings.testing;

						if (_.isObject(settings))
						{
							if (settings.status)
							{
								if (!_.isUndefined(context)) {console.log('[' + context + ']:')}
								console.log(message);

								if (!_.isUndefined(settings.break))
								{
									console.log(settings.break)
								}
							}
						}	
					},

					data: function (data, context)
					{
						var settings = module.exports.data.settings.testing;

						if (_.isObject(settings))
						{
							if (settings.status && settings.showData)
							{
								if (_.isObject(data))
								{
									data = JSON.stringify(data)
								}

								if (!_.isUndefined(context)) {console.log('[' + context + '][data]:')}
								console.log(data);

								if (!_.isUndefined(settings.break))
								{
									console.log(settings.break)
								}	
							}
						}	
					},

					status: function (status)
					{
						var settings = module.exports.data.settings.testing;

						if (_.isObject(settings))
						{
							if (_.isUndefined(status))
							{
								status = module.exports.data.settings.testing.status;
							}
							else
							{
								module.exports.data.settings.testing.status = status;
							}
						}

						return status
					}
				},

				search:  
				{	
					init: function ()
					{
						var criteria = 
						{
							"fields": [],
							"summaryFields": [],
							"filters": [],
							"sorts": [],
							"options": {},
							"customoptions": []
						}

						return criteria
					}
				},

				hash: function (data)
				{
					var crypto = require('crypto');
					return crypto.createHash('md5').update(data).digest("hex");
				},

				doCallBack: function()
				{
					var param, callback, data;

					if (typeof arguments[0] == 'function')
					{
						callback = arguments[0]
						param = arguments[1] || {};
						data = arguments[2]
					}
					else
					{
						param = arguments[0] || {};
						callback = param.callback;
						data = arguments[1];
						delete param.callback;
					}

					if (callback)
					{
						callback(param, data)
					};
				},

				onComplete: function (param)
				{
					if (module.exports._util.param.get(param, 'onComplete').exists)
					{
						var onComplete = module.exports._util.param.get(param, 'onComplete').value;
	
						if (module.exports._util.param.get(param, 'onCompleteWhenCan').exists)
						{
							param.onComplete = param.onCompleteWhenCan;
							delete param.onCompleteWhenCan;
						}	
						else
						{
							delete param.onComplete;
						}

						onComplete(param);
					}
					else if (module.exports._util.param.get(param, 'onCompleteWhenCan').exists)
					{
						var onCompleteWhenCan = module.exports._util.param.get(param, 'onCompleteWhenCan').value;

						delete param.onCompleteWhenCan;
					
						onCompleteWhenCan(param);
					}
				},

	param: 	{
					get: 		function(param, name, options)
								{
									if (param == undefined) {param = {}}
									if (options == undefined) {options = {}}
							
									var data = {exists: false, value: options.default};

									var split = options.split;
									var index = options.index;
									var remove = options.remove;	
									var set = options.set;
								
									if (param.hasOwnProperty(name))
									{
										if (param[name] != undefined) {data.value = param[name]};
										data.exists = true;

										if (index !== undefined && split === undefined) {split = '-'}

										if (split !== undefined)
										{
											if (param[name] !== undefined)
											{	
												data.values = param[name].split(split);

												if (index !== undefined)
												{
													if (index < data.values.length)
													{
														data.value = data.values[index];
													}
												}
											}	
										}

										if (remove) {delete param[name]};
										if (set) {param[name] = data.value};
									}

									return data;
								},

					set: 		function(param, key, value, options)
								{
									var onlyIfNoKey = false;

									if (module.exports._util.param.get(options, 'onlyIfNoKey').exists)
									{
										onlyIfNoKey = module.exports._util.param.get(options, 'onlyIfNoKey').value
									}

									if (param === undefined) {param = {}}

									if (param.hasOwnProperty(key))
									{
										if (!onlyIfNoKey) {param[key] = value};
									}
									else
									{
										param[key] = value;
									}
										
									return param
								}									
				},

				logoff: 	function (param, response)
				{
					var uri = module.exports._util.param.get(param, 'uri', {"default": '/'}).value;
					var refresh = module.exports._util.param.get(param, 'refresh', {"default": true}).value;

					if (_.isUndefined(response))
					{
						module.exports.send(
						{
							url: '/rpc/core/?method=CORE_LOGOFF'
						},
						'',
						module.exports._util.logoff);
					}
					else
					{
						module.exports._util.testing.log('Logged off', 'mydigitalstructure._util.logoff');
						module.exports.data.session = undefined;
					}	
				}			
			}							
}