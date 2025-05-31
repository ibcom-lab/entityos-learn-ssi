/*
	ENTITYOS SSI API
	
	https://ssi.api.entityos.cloud

	SSI Util Functions (For Future)
	node_modules/ssifactory/

	References:
	https://selfdriven.foundation/trust
	https://selfdriven.foundation/identity

	“ssi-get-info"
	“ssi-generate-did-document”,
	“ssi-generate-account”,
	“ssi-generate-verifiable-credential” // Use EntityOS SSI Service DID as the issuer and User DID as the controller

	“ssi-get-did-docs”
	“ssi-get-did-conns”
	
	“ssi-get-verifiable-presentations”,

	Depends on;
	https://learn.entityos.cloud/learn-function-automation

	---

	This is a lambda compliant node app with a wrapper to process data from API Gateway & respond to it.

	To run it on your local computer your need to install
	https://www.npmjs.com/package/lambda-local and then run as:

	lambda-local -l index.js -t 9000 -e event.json

	API Gateway docs:
	- https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
	
	Authentication:
	Get apikey in the event data, and using user in settings.json get the username based on matching GUID
	The use the authKey in the event data as the password with the username.
	!! In production make sure the settings.json is unrestricted data with functional restriction to setup_user
	!!! The apiKey user has restricted data (based on relationships) and functional access

	Event Data:
	{
	  "body": {
	    "apikey": "e7849d3a-d8a3-49c7-8b27-70b85047e0f1"
	  },
	  "queryStringParameters": {},
	  "headers": {}
	}

	event/passed data available via request contect in the app scope.
	eg
		var request = entityos.get(
		{
			scope: 'app',
			context: 'request'
		});
		
		>

		{ 
			body: {},
			queryString: {},
			headers: {}
		}

	"app-auth" checks the apikey sent against users in the space (as per settings.json)
	
	Run:
	lambda-local -l index.js -t 9000 -e event-ssi-get-info-lab.json
	lambda-local -l index.js -t 9000 -e event-ssi-generate-did-document-lab.json
	lambda-local -l index.js -t 9000 -e event-ssi-generate-account-lab.json

	lambda-local -l index.js -t 9000 -e event-ssi-generate-verifiable-credential-lab.json
	lambda-local -l index.js -t 9000 -e event-ssi-generate-verifiable-credential-with-data-lab.json
	lambda-local -l index.js -t 9000 -e event-ssi-generate-verifiable-credential-with-data-saveproof-lab.json
	
	Upload to AWS Lambda:
	zip -r ../entityos-ssi-DDMMMYYYY-n.zip *
*/

exports.handler = function (event, context, callback)
{
	var entityos = require('entityos');
	var _ = require('lodash')
	var moment = require('moment');
	var entityosProtect = require('entityos/entityos.protect.js');

	entityos._util.message(event)

	if (event.isBase64Encoded)
	{
		event.body = Buffer.from(event.body, 'base64').toString('utf-8');
	}

	console.log(event)

	if (_.isString(event.body))
	{
		if (_.startsWith(event.body, 'ey'))
		{
			event.body = JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8'));
		}
		else
		{
			event.body = JSON.parse(event.body);
		}
	}

	if (_.isString(event.body.data))
	{
		if (_.startsWith(event.body.data, 'ey'))
		{
			event.body.data = JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8'));
		}
		else
		{
			event.body.data = JSON.parse(event.body.data);
		}
	}

	if (_.has(event, 'body._context'))
	{
		event.context = event.body._context;
	}

	entityos.set(
	{
		scope: '_event',
		value: event
	});

	entityos.set(
	{
		scope: '_context',
		value: context
	});

	/*
		Use promise to responded to API Gateway once all the processing has been completed.
	*/

	const promise = new Promise(function(resolve, reject)
	{	
		entityos.init(main);

		function main(err, data)
		{
			/*
				app initialises with entityos.invoke('app-init') after controllers added.
			*/

			entityos.add(
			{
				name: 'app-init',
				code: function ()
				{
					entityos._util.message('Using entityos module version ' + entityos.VERSION);
					entityos._util.message(entityos.data.session);

					var eventData = entityos.get(
					{
						scope: '_event'
					});

					var request =
					{ 
						body: {},
						queryString: {},
						headers: {}
					}

					if (eventData != undefined)
					{
						request.queryString = eventData.queryStringParameters;
						request.headers = eventData.headers;

						if (_.isString(eventData.body))
						{
							request.body = JSON.parse(eventData.body)
						}
						else
						{
							request.body = eventData.body;
						}	
					}

					if (request.headers['x-api-key'] != undefined)
					{
						var _xAPIKey = _.split(request.headers['x-api-key'], '|');
						
						if (_xAPIKey.length == 0)
						{
							entityos.invoke('util-end', {error: 'Bad x-api-key in header [' + request.headers['x-api-key'] + '] - it should be {apiKey} or {apiKey}|{authKey}.'}, '401');
						}
						else
						{
							if (_xAPIKey.length == 1)
							{
								request.body.apikey = _xAPIKey[0];
							}
							else
							{
								request.body.apikey = _xAPIKey[0];
								request.body.authkey = _xAPIKey[1];
							}
						}
					}

					if (request.headers['x-auth-key'] != undefined)
					{
						request.body.authkey = request.headers['x-auth-key'];
					}

					entityos.set(
					{
						scope: '_request',
						value: request
					});

					entityos.set(
					{
						scope: '_data',
						value: request.body.data
					});

					if (request.body.apikey != undefined)
					{
						if (request.body.authkey != undefined)
						{
							entityos.invoke('app-auth');
						}
						else
						{
							if (request.body.method == 'ssi-get-info')
							{
								entityos.invoke('app-start');
							}
							else
							{
								entityos.invoke('util-end', {error: 'Missing authKey'}, '401');
							}
						}
					}
					else
					{
						entityos.invoke('app-start');
					}
				}
			});

			entityos.add(
			{
				name: 'app-auth',
				code: function (param)
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var requestApiKeyGUID = request.body.apikey;

					entityos.cloud.search(
					{
						object: 'setup_user',
						fields: [{name: 'username'}],
						filters:
						[
							{
								field: 'guid',
								comparison: 'EQUAL_TO',
								value: requestApiKeyGUID
							}
						],
						callback: 'app-auth-process'
					});
				}
			});

			entityos.add(
			{
				name: 'app-auth-process',
				code: function (param, response)
				{
					entityos.set(
					{
						scope: 'app',
						context: 'user',
						value: response
					});

					if (response.status == 'ER')
					{
						entityos.invoke('util-end', {error: 'Error processing user authentication.'}, '401');
					}
					else
					{
						if (response.data.rows.length == 0)
						{
							var request = entityos.get(
							{
								scope: '_request'
							});

							var requestApiKeyGUID = request.body.apikey;

							entityos.invoke('util-end', {error: 'Bad apikey [' + requestApiKeyGUID + ']'}, '401');
						}
						else
						{
							var user = _.first(response.data.rows);

							var request = entityos.get(
							{
								scope: '_request'
							});

							var requestAuthKeyGUID = request.body.authkey;

							entityos.logon('app-auth-logon-process',
							{
								logon: user.username,
								password: requestAuthKeyGUID
							});
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-auth-logon-process',
				code: function (response)
				{
					if (response.status == 'ER')
					{
						var request = entityos.get(
						{
							scope: '_request'
						});

						var requestAuthKeyGUID = request.body.authkey;

						if (response.error.errornotes == 'LogonKey has not been requested')
						{
							entityos.invoke('util-end', {error: 'Bad authkey user config. Set authenticationlevel=1. [' + requestAuthKeyGUID + ']'}, '401');
						}
						else
						{
							entityos.invoke('util-end', {error: 'Bad authkey [' + requestAuthKeyGUID + ']'}, '401');
						}
					}
					else
					{
						entityos.set(
						{
							scope: 'app',
							context: 'user',
							value: response
						});

						entityos.invoke('app-user');
					}
				}
			});

			entityos.add(
			{
				name: 'app-user',
				code: function (param)
				{
					entityos.cloud.invoke(
					{
						method: 'core_get_user_details',
						callback: 'app-user-process'
					});
				}
			});

			entityos.add(
			{
				name: 'app-user-process',
				code: function (param, response)
				{
					entityos.set(
					{
						scope: 'app',
						context: 'user',
						value: response
					})

					entityos.invoke('app-start')
				}
			});

			entityos.add(
			{
				name: 'util-uuid',
				code: function (param)
				{
					var pattern = entityos._util.param.get(param, 'pattern', {"default": 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'}).value;
					var scope = entityos._util.param.get(param, 'scope').value;
					var context = entityos._util.param.get(param, 'context').value;

					var uuid = pattern.replace(/[xy]/g, function(c) {
						    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
						    return v.toString(16);
						  });

					entityos.set(
					{
						scope: scope,
						context: context,
						value: uuid
					})
				}
			});

			entityos.add(
			{
				name: 'app-log',
				code: function ()
				{
					var eventData = entityos.get(
					{
						scope: '_event'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(eventData),
							notes: 'app Log (Event)'
						}
					});

					var requestData = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(requestData),
							notes: 'app Log (Request)'
						}
					});

					var contextData = entityos.get(
					{
						scope: '_context'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(contextData),
							notes: 'appLog (Context)'
						},
						callback: 'app-log-saved'
					});
				}
			});

			entityos.add(
			{
				name: 'app-log-saved',
				code: function (param, response)
				{
					entityos._util.message('Log data saved to entityos.cloud');
					entityos._util.message(param);
					entityos._util.message(response);
				
					entityos.invoke('app-respond')
				}
			});

			entityos.add(
			{
				name: 'app-respond',
				code: function (param)
				{
					var response = entityos.get(
					{
						scope: 'app',
						context: 'response'
					});

					var statusCode = response.httpStatus;
					if (statusCode == undefined) {statusCode = '200'}

					var body = response.data;
					if (body == undefined) {body = {}}
					
					var headers = response.headers;
					if (headers == undefined) {headers = {}}

					let httpResponse =
					{
						statusCode: statusCode,
						headers: headers,
						body: JSON.stringify(body)
					};

					resolve(httpResponse)
				}
			});

			entityos.add(
			{
				name: 'util-end',
				code: function (data, statusCode, headers)
				{
					if (statusCode == undefined) { statusCode = '200' }
					if (headers == undefined) { headers = {'Content-Type': 'application/json'} }

					entityos.set(
					{
						scope: 'app',
						context: 'response',
						value:
						{
							data: data,
							statusCode: statusCode,
							headers: headers
						}
					});

					entityos.invoke('app-respond')
				}
			});

			entityos.add(
			{
				name: 'app-start',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body;
					var mode = data.mode;
					var method = data.method;

					if (_.isString(mode))
					{
						mode = {type: mode, status: 'OK'}
					}

					if (mode == undefined)
					{
						mode = {type: 'live', status: 'OK'}
					}

					if (mode.status == undefined)
					{
						mode.status = 'OK';
					}

					mode.status = mode.status.toUpperCase();

					if (mode.type == 'reflect')
					{
						var response = {}

						if (mode.data != undefined)
						{
							response.data = mode.data;
						}
						
						entityos.invoke('util-uuid',
						{
							scope: 'guid',
							context: 'log'
						});

						entityos.invoke('util-uuid',
						{
							scope: 'guid',
							context: 'audit'
						});

						response.data = _.assign(response.data,
						{
							status: mode.status,
							method: method,
							reflected: data,
							guids: entityos.get(
							{
								scope: 'guid'
							})
						});

						entityos.set(
						{
							scope: 'app',
							context: 'response',
							value: response
						});

						entityos.invoke('app-respond');
					}
					else
					{
						entityos.invoke('app-process');
					}
				}
			});

			//-- METHODS

			entityos.add(
			{
				name: 'app-process',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body;

					var method = data.method;
	
					if (_.includes(
					[
						'ssi-get-info',
						'ssi-generate-did-document',
						'ssi-generate-account',
						'ssi-generate-verifiable-credential',
						'--ssi-get-did-documents',
						'--ssi-get-did-connections',
						'--ssi-get-verifiable-presentations',
						'ssi-get-did',
					],
						method))
					{
						entityos.invoke('app-process-' + method)
					}
					else
					{
						entityos.set(
						{
							scope: 'app',
							context: 'response',
							value:
							{
								status: 'ER',
								data: {error: {code: '2', description: 'Not a valid method [' + method + ']'}}
							}
						});

						entityos.invoke('app-respond');
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-get-info',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					if (data == undefined)
					{
						entityos.invoke('util-end', 
						{
							error: 'Missing data.'
						},
						'403');
					}
					else
					{
						const settings = entityos.get(
						{
							scope: '_settings'
						});

						let specifications = _.get(settings, 'ssi.specifications', {});
						let frameworks = _.get(settings, 'ssi.frameworks', {});
						const entityOSDIDDocument = entityos.invoke('util-ssi-create-did-document', {useentityOSKeys: true});

						var responseData =
						{
							"specifications": specifications,
							"frameworks": frameworks,
							"entityOS": {"did": {"document": entityOSDIDDocument}}
						}

						entityos.invoke('util-end',
						{
							method: 'app-process-ssi-get-info',
							status: 'OK',
							data: responseData
						},
						'200');
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-get-did',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = entityos.get({scope: '_data'});

					if (data == undefined)
					{
						entityos.invoke('util-end', 
						{
							error: 'Missing data.'
						},
						'403');
					}
					else
					{
						const settings = entityos.get(
						{
							scope: '_settings'
						});

						const nameFormat = _.get(data, 'nameformat', 'plc');
						const host = event.requestContext.domainName; //eg entityOS.selfdriven.social

						// Get a return the did linked to the domain name that came in on the event

						let specifications = _.get(settings, 'ssi.specifications', {});
						let frameworks = _.get(settings, 'ssi.frameworks', {});
						const entityOSDIDDocument = entityos.invoke('util-ssi-create-did-document', {useentityOSKeys: true});

						var responseData =
						{
							"specifications": specifications,
							"frameworks": frameworks,
							"entityOS": {"did": {"document": entityOSDIDDocument}}
						}

						entityos.invoke('util-end',
						{
							method: 'app-process-ssi-get-info',
							status: 'OK',
							data: responseData
						},
						'200');
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account',
				code: function ()
				{
					entityos.invoke('app-process-ssi-generate-did-document')
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-did-document',
				code: function ()
				{
					var entityosProtect = require('entityos/entityos.protect.js');

					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					if (data == undefined)
					{
						entityos.invoke('util-end', 
						{
							error: 'Missing data.'
						},
						'403');
					}
					else
					{
						const settings = entityos.get(
						{
							scope: '_settings'
						});

						const frameworkName = _.get(data, 'ssiframework', 'selfdriven').toLowerCase();

						const framework = _.find(settings.ssi.frameworks, function (framework)
						{
							return (framework.name == frameworkName)
						});

						if (framework == undefined)
						{
							entityos.invoke('util-end', 
							{
								error: 'Invalid framework'
							},
							'403');
						}
						else
						{
							let didMethodName = _.get(data, 'didmethod');

							if (didMethodName == undefined)
							{
								didMethodName = frameworkName;
							}

							const didMethod = _.find(framework.did.methods, function (method)
							{
								return (method.name == didMethodName)
							});

							if (didMethod == undefined)
							{
								entityos.invoke('util-end', 
								{
									error: 'Invalid didmethod'
								},
								'403');
							}
							else
							{	
								const didMethodSpecification = _.find(settings.ssi.specifications, function (specification)
								{
									return (specification.name == didMethod.specification)
								});

								if (didMethodSpecification == undefined)
								{
									entityos.invoke('util-end', 
									{
										error: 'Invalid didmethod.specification'
									},
									'403');
								}
								else
								{
									let curveType = _.get(data, 'curve');

									if (curveType == undefined)
									{
										curveType = didMethodSpecification.curve;
									}

									//console.log('Curve: ' + curveType);
						
									const EC = require('elliptic').ec;
									const ec = new EC(curveType);

									const _curveKeyPair = ec.genKeyPair();

									const curveKeys =
									{
										public: {hex: _curveKeyPair.getPublic('hex')},
										private: {hex: _curveKeyPair.getPrivate('hex')}
									}

									//console.log(curveType + ' Key Pair:')
							
									curveKeys.public.base58 = entityosProtect.convert(
									{
										input: 'hex',
										output: 'base58',
										text: curveKeys.public.hex
									}).textConverted;

									curveKeys.public.sha256Hex = entityosProtect.hash(
									{
										output: 'hex',
										text: curveKeys.public.hex
									}).textHashed;

									//console.log(curveKeys);

									const ssiDID = 'did:' + didMethodName + ':' + curveKeys.public.base58;
									
									//console.log('DID:', ssiDID);

									const multibasePrefixes =
									{
										base58: 'z',
										base16: 'f',
										hex: 'f',
										base32: 'b',
										base64: 'Q',
										base64padding: 'm',
										base64urlsafe: 'u'
									}
								
									let didDocument = {
										id: ssiDID,
										verificationMethod:
										[
											{
												id: ssiDID + '#keys-1',
												type: didMethodSpecification.keyVerificationType,
												controller: ssiDID
										}],
										authentication: [{
											type: didMethodSpecification.keyAuthenticationType,
											publicKey: ssiDID + '#keys-1'
										}],
										service: []
									}

									_.each(didDocument.verificationMethod, function (method)
									{
										if (_.includes(didMethodSpecification.publicKey.name, 'Multibase'))
										{
											method[didMethodSpecification.publicKey.name] =
												multibasePrefixes[didMethodSpecification.publicKey.encoding] +
												curveKeys.public[didMethodSpecification.publicKey.encoding];
										}
										else
										{
											method[didMethodSpecification.publicKey.name] = curveKeys.public[didMethodSpecification.publicKey.encoding];
										}
									});

									didDocument['@context'] = 'https://www.w3.org/ns/did/v1';

									didDocument.service.push(
									{
										id: ssiDID + '#did-resolver-service',
										type: 'DIDResolver',
										serviceEndpoint: 'http://ssi.api.entityos.cloud/get-did-document'
									});

									didDocument.service.push(
									{
										id: ssiDID + '#did-revocation-status-service',
										type: 'RevocationList2020',
										serviceEndpoint: 'http://ssi.api.entityos.cloud/get-did-revocation-status'
									});

									didDocument.service.push(
									{
										id: ssiDID + '#credential-status-service',
										type: 'CredentialStatusList2020',
										serviceEndpoint: 'http://ssi.api.entityos.cloud/get-verifiable-credential-status'
									});

									//console.log(didDocument)

									const didDocumentFormatted = JSON.stringify(didDocument, null, 2)

									if (request.body.method == 'ssi-generate-account')
									{
										entityos.set(
										{
											scope: 'ssi-generate-account',
											value:
											{
												curveKeys: curveKeys,
												didDocument: didDocument
											}
										});

										entityos.invoke('app-process-ssi-generate-account-process');
									}
									else
									{
										var responseData =
										{
											"did": 
											{
												"document": didDocument,
												"documentFormatted": didDocumentFormatted
											}
										}

										entityos.invoke('util-end',
										{
											method: 'ssi-generate-did-document',
											status: 'OK',
											data: responseData
										},
										'200');
									}
								}
							}
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account-process',
				code: function ()
				{
					entityos.invoke('app-process-ssi-generate-account-process-conversation')
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account-process-conversation',
				code: function ()
				{
					//Verify that the user making the API request has the authority to create the account
					//Do this via messaging_conversation
					//Requestor has to be the owner of the conversation that the post "Create account" relates to.
					//entityOS is a participant
					//AuthKey == Conversation Post GUID

					//request.userkey - for account.
					//request.conversationkey or request.conversationpostkey

					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					if (data == undefined)
					{
						data = {}
					}

					const keys = 
					{
						user: data.userkey,
						conversation: data.conversationkey
					}

					if (keys.user == undefined || keys.post)
					{
						entityos.invoke('util-end', {error: 'Missing User &/or Conversation/Post Key'}, '401');
					}
					else
					{
						//This will prove both keys.
						//Have to do double pass as no subsearch to owner user GUID.

						entityos.cloud.search(
						{
							object: 'messaging_conversation',
							fields: [{name: 'owner'}],
							filters:
							[
								{
									field: 'guid',
									comparison: 'EQUAL_TO',
									value: keys.conversation
								},
								{
									field: 'sharing',
									comparison: 'EQUAL_TO',
									value: 1
								}
							],
							callback: 'app-process-ssi-generate-account-process-conversation-response'
						});
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account-process-conversation-response',
				code: function (param, response)
				{
					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					const keys = 
					{
						user: data.userkey,
						conversation: data.conversationkey
					}

					if (response.data.rows.length == 0)
					{
						entityos.invoke('util-end', {error: 'Bad Conversation Key'}, '401');
					}
					else
					{
						const conversation = _.first(response.data.rows);

						entityos.cloud.search(
						{
							object: 'setup_user',
							fields: [{name: 'createddate'}],
							filters:
							[
								{
									field: 'guid',
									comparison: 'EQUAL_TO',
									value: keys.user
								},
								{
									field: 'id',
									comparison: 'EQUAL_TO',
									value: conversation.owner
								}
							],
							callback: 'app-process-ssi-generate-account-process-user-response'
						});
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account-process-user-response',
				code: function (param, response)
				{
					//Verify that the user making the API request has the authority to create the account
					//Do this via messaging_conversation
					//Requestor has to be the owner of the conversation that the post "Create account" relates to.
					//entityOS is a participant
					//AuthKey == Conversation Post GUID

					//request.userkey - for account.
					//request.conversationpostkey

					var request = entityos.get({scope: '_request'});
					var data = request.body.data;

					if (response.data.rows.length == 0)
					{
						entityos.invoke('util-end', {error: 'Bad User Key (Not The Conversation Owner)'}, '401');
					}
					else
					{
						let event = entityos.get({scope: '_event'});
						event._user = _.first(response.data.rows);
						entityos.set({scope: '_event', value: event});
						entityos.invoke('app-process-ssi-generate-account-process-save')
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account-process-save',
				code: function (param, response)
				{
					const request = entityos.get({scope: '_request'});
					const data = request.body.data;
					const event = entityos.get({scope: '_event'});

					if (response == undefined)
					{
						entityos.cloud.search(
						{
							object: 'core_protect_key',
							fields: [{name: 'key'}, {name: 'notes'}],
							filters:
							[
								{
									field: 'object',
									comparison: 'EQUAL_TO',
									value: 22
								},
								{
									field: 'objectcontext',
									comparison: 'EQUAL_TO',
									value: event._user.id
								},
								{
									field: 'category',
									comparison: 'EQUAL_TO',
									value: 4
								},
								{
									field: 'type',
									comparison: 'EQUAL_TO',
									value: 2
								},
								{
									field: 'private',
									comparison: 'EQUAL_TO',
									value: 'Y'
								},
								{
									field: 'title',
									comparison: 'EQUAL_TO',
									value: '[ssi-account-fully-managed]'
								}
							],
							callback: 'app-process-ssi-generate-account-process-save'
						});
					}
					else
					{
						let ssiAccount = entityos.get(
						{
							scope: 'ssi-generate-account'
						});

						let keyID;
						let keyNotes;

						if (response.data.rows != 0)
						{
							keyID = _.first(response.data.rows).id;
							keyNotes = _.first(response.data.rows).notes;
						}

						const cloudSave = (keyID == undefined || (keyID != undefined && data.reset == true)); 

						if (!cloudSave)
						{
							let keyDIDDocument;

							if (_.startsWith(keyNotes, '{'))
							{
								keyDIDDocument = JSON.parse(keyNotes);
							}

							entityos.invoke('util-end',
							{	
								method: 'ssi-generate-account',
								data:
								{
									didDocument: keyDIDDocument,
									warning: 'Identity (SSI) account already exists - use reset:true to reset it.'
								}
							}, '200');
						}
						else
						{
							//AES encrypt the mnemonic|passphrase using entityOS settings

							let keyInfo = JSON.stringify(
							{
								publicHex: ssiAccount.curveKeys.publicHex,
								privateHex: ssiAccount.curveKeys.privateHex
							});

							const settings = entityos.get({scope: '_settings'});

							const key = _.get(settings, 'protect.key');
							const iv = _.get(settings, 'protect.iv');

							// Key IV Stored Against this entityOS API User.
							const encrypted = entityosProtect.encrypt(
							{
								text: keyInfo,
								key: key,
								iv: iv
							});

							const notes = JSON.stringify(ssiAccount.didDocument);

							entityos.cloud.save(
							{
								object: 'core_protect_key',
								data:
								{
									category: 4, //identity
									key: encrypted.textEncrypted, //public & private keys - encypted
									object: 22,
									objectcontext: event._user.id,
									type: 2,
									private: 'Y', // To entityOS (API) has custody
									title: '[ssi-account-fully-managed]',
									notes: notes,
									id: keyID
								},
								callback: 'app-process-ssi-generate-account-process-finalise'
							});
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-account-process-finalise',
				code: function (param)
				{
					let ssiAccount = entityos.get(
					{
						scope: 'ssi-generate-account'
					});

					var responseData =
					{
						didDocument: ssiAccount.didDocument
					}
					
					entityos.invoke('util-end',
					{
						method: 'ssi-generate-account',
						status: 'OK',
						data: responseData
					},
					'200');
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-verifiable-credential',
				code: function (param, response)
				{
					// Based on userkey/action(achievementkey)
					// Check valid action id 
					// Then check that user has rights to create VC - like do for account based on user/conversation key
					// 		But for now OK that they know the key (Action.GUID) 

					const data =  entityos.get({scope: '_data'});
					const achievementKey = _.get(data, 'achievementkey');

					if (achievementKey == undefined)
					{
						entityos.invoke('util-end', {error: 'Missing Achievement Key'}, '401');
					}
					else
					{
						const achievementText = _.get(data, 'achievementtext');
						const achievementByKey = _.get(data, 'achievementbykey');
						const achievementDate = _.get(data, 'achievementdate');
						const achievementID = _.get(data, 'achievementid');

						if (achievementText == undefined || achievementByKey == undefined)
						{
							entityos.invoke('app-process-ssi-generate-verifiable-credential-action', param);
						}
						else
						{
							data._achievementAction = {
								'action.contactperson.guid': achievementByKey,
								'guid': achievementKey,
								'text': achievementText,
								'modifieddate': achievementDate,
								'id': achievementID
							}

							data.achievementID = 'urn:uuid:' + data._achievementAction.guid;
							data.achievementByID = 'urn:uuid:' + data._achievementAction['action.contactperson.guid'];
						}

						if (_.startsWith(data._achievementAction.text, '['))
						{
							data._achievementAction._skills = JSON.parse(data._achievementAction.text);
						}

						entityos.invoke('app-process-ssi-generate-verifiable-credential-process');						
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-verifiable-credential-action',
				code: function (param, response)
				{
					// Based on userkey/action(achievementkey)
					// Check valid action id 
					// Then check that user has rights to create VC - like do for account based on user/conversation key
					// 		But for now OK that they know the key (Action.GUID) 

					const data =  entityos.get({scope: '_data'});
					const settings =  entityos.get({scope: '_settings'});
					const achievementKey = _.get(data, 'achievementkey');

					if (response == undefined)
					{
						if (achievementKey == undefined)
						{
							entityos.invoke('util-end', {error: 'Missing Achievement Key'}, '401');
						}
						else
						{
							entityos.cloud.search(
							{
								object: 'action',
								fields: [{name: 'text'}, {name: 'guid'}, {name: 'modifieddate'}, {name: 'action.contactperson.guid'}],
								filters:
								[
									{
										field: 'guid',
										comparison: 'EQUAL_TO',
										value: achievementKey
									},
									{
										field: 'type',
										comparison: 'IN_LIST',
										value: settings.selfdriven.actionTypes.achievement
									}
									
								],
								callback: 'app-process-ssi-generate-verifiable-credential-action'
							});
						}
					}
					else
					{
						if (response.status == 'ER' || _.get(response, 'data.rows', []).length == 0)
						{
							entityos.invoke('util-end', {error: 'Bad Achievement Key'}, '401');
						}
						else
						{
							data._achievementAction = _.first(response.data.rows);
							data.achievementID = 'urn:uuid:' + data._achievementAction.guid;
							data.achievementByID = 'urn:uuid:' + data._achievementAction['action.contactperson.guid'];

							if (_.startsWith(data._achievementAction.text, '['))
							{
								data._achievementAction._skills = JSON.parse(data._achievementAction.text);
							}

							entityos.invoke('app-process-ssi-generate-verifiable-credential-process');
						}
					}

				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-verifiable-credential-process',
				code: function ()
				{			
					// Get entityOS keys as Signer/Issuer for selfdriven

					const data =  entityos.get({scope: '_data'});
					const settings =  entityos.get({scope: '_settings'});

					const signPublicKeyHex = _.get(settings, 'protect.sign.publicKeyHex');
					const signPrivateKeyHex = _.get(settings, 'protect.sign.privateKeyHex');
					
					if (signPrivateKeyHex == undefined || signPublicKeyHex == undefined)
					{
						entityos.invoke('util-end', {error: 'entityOS key identity is not set.'}, '401');
					}
					else
					{
						const crypto = require('crypto');

						//Signed by EntityOS SSI Service by default.
						//entityOS as issuer - using entityOS SSI DID Document

						const signPublicKeyBase58 = entityosProtect.convert(
						{
							input: 'hex',
							output: 'base58',
							text: signPublicKeyHex
						}).textConverted;


						// As per entityOS DID Document (reconstructed)
						// https://selfdriven.id/ssi

						const entityOSDID = 'did:selfdriven:' + signPublicKeyBase58;

						//"https://www.w3.org/2018/credentials/examples/v1" -- add to spec for skillzeb context JSON-LD

						let achievementByID = data.achievementByID;
						// todo: see if they have a did

						let credentialSubjects = []

						_.each(data._achievementAction._skills, function (skill)
						{
							credentialSubjects.push(
							{
								"id": achievementByID,
								"skillId": 'urn:uuid:' + skill.guid,
								"skillName": skill.skilltext
							})
						});

						const dataVerifiableCredential =
						{
							"@context": [
								"https://www.w3.org/2018/credentials/v1"
							],
							"id": data.achievementID,
							"type": ["VerifiableCredential", "SkillCredential"],
							"issuer": entityOSDID,
							"issuanceDate": moment(data._achievementAction.modifieddate, 'DD MMM YYYY HH:mm:ss').toISOString(),
							"credentialSubject": credentialSubjects
						};
			
						const entityOSDIDVerificationMethod = entityOSDID + '#keys-1';
						
						const elliptic = require('elliptic');
						const base64url = require('base64url');

						const ed25519 = new elliptic.eddsa('ed25519');

						// Function to convert hex to Buffer
						// todo: use Buffer?
						function hexToBuffer(hexString)
						{
							return Buffer.from(hexString, 'hex');
						}

						console.log(data)

						function signJWT(header, payload, privateKeyHex)
						{
							const encodedHeader = base64url(JSON.stringify(header));
							const encodedPayload = base64url(JSON.stringify(payload));
							const signingData = encodedHeader + '.' + encodedPayload;

							const keyPair = ed25519.keyFromSecret(privateKeyHex);

							const signature = keyPair.sign(crypto.createHash('sha512').update(signingData).digest()).toHex();

							const encodedSignature = base64url(hexToBuffer(signature));

							return signingData + '.' + encodedSignature;
						}

						const header =
						{
							alg: 'EdDSA',
							typ: 'JWT'
						};

						//achievementByID is urn:uuid - need to check if did exists and then use urn:uuid as back up

						const payload =
						{
							iss: entityOSDID,
							sub: achievementByID,
							vc: dataVerifiableCredential,
							exp: Math.floor(Date.now() / 1000) + 30758400 // 365 days from now
						};

						const privateKeyHex = signPrivateKeyHex

						try
						{
							const jwt = signJWT(header, payload, privateKeyHex);

							const proof =
							{
								type: 'Ed25519Signature2020', // Signature type
								created: new Date().toISOString(), // When the signature was created
								proofPurpose: 'assertionMethod', // Purpose of the proof
								verificationMethod: entityOSDIDVerificationMethod, // Public key or DID used to verify
								jws: base64url(jwt) // The signature (JWS format)
							};

							data.signedCredential =
							{
								...dataVerifiableCredential,
								proof
							};

							console.log(data)

							if (_.get(data, 'saveproof', false))
							{
								entityos.invoke('app-process-ssi-generate-verifiable-credential-save');
							}
							else
							{
								entityos.invoke('app-process-ssi-generate-verifiable-credential-finalise');
							}
						}
						catch (error)
						{
							entityos.invoke('util-end', {error: 'Error creating proof signature:' + error}, '400');
							console.error('Error creating proof signature:', error);
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-verifiable-credential-save',
				code: function ()
				{			
					const settings =  entityos.get({scope: '_settings'});
				
					const data =  entityos.get({scope: '_data'});

					console.log(data.signedCredential);

					const cipherText = data.signedCredential.proof.jws;
					const sourceText = Buffer.from(JSON.stringify(data.signedCredential), 'utf-8').toString('base64') ;

					if (_.get(data, 'saveproof', false))
					{
						const signPublicKeyID = _.get(settings, 'protect.sign.publicKeyID');

						const saveData =
						{
							key: signPublicKeyID,
							ciphertext: cipherText,
							sourcetext: sourceText,
							object: 17,
							objectcontext: data._achievementAction.id,
							type: 1,
							notes: '[achievement-ssi]'
						}

						entityos.cloud.save(
						{
							object: 'core_protect_ciphertext',
							data: saveData,
							callback: 'app-process-ssi-generate-verifiable-credential-save-response'
						});
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-ssi-generate-verifiable-credential-save-response',
				code: function (param, response)
				{
					if (response.status == 'ER')
					{
						entityos.invoke('util-end', {error: 'Error saving the credential proof.'}, '403');
					}
					else
					{
						let data =  entityos.get({scope: '_data'});
						data.saveproofid = response.id;
						entityos.invoke('app-process-ssi-generate-verifiable-credential-finalise');
					}

				}
			});		

			entityos.add(
			{
				name: 'app-process-ssi-generate-verifiable-credential-finalise',
				code: function ()
				{			
					const data =  entityos.get({scope: '_data'});

					var responseData =
					{
						verifiableCredential: data.signedCredential
					}

					if (data.saveproofid != undefined)
					{
						responseData.saveproofid = data.saveproofid;
					}
					
					entityos.invoke('util-end',
					{
						method: 'ssi-generate-verifiable-credential',
						status: 'OK',
						data: responseData
					},
					'200');

				}
			});

			entityos.add(
			{
				name: 'util-ssi-base64-url-encode',
				code: function (data)
				{
					return Buffer.from(data)
						.toString('base64')
						.replace(/=/g, '')  // Remove padding '='
						.replace(/\+/g, '-') // Replace '+' with '-'
						.replace(/\//g, '_'); // Replace '/' with '_'
				}
			});

			entityos.add(
			{
				name: 'util-ssi-create-did-document',
				code: function (param)
				{
					var entityosProtect = require('entityos/entityos.protect.js');

					var request = entityos.get(
					{
						scope: '_request'
					});

					var data = request.body.data;

					if (data == undefined)
					{
						entityos.invoke('util-end', 
						{
							error: 'Missing data.'
						},
						'403');
					}
					else
					{
						const settings = entityos.get(
						{
							scope: '_settings'
						});

						const frameworkName = _.get(data, 'ssiframework', 'selfdriven').toLowerCase();

						const framework = _.find(settings.ssi.frameworks, function (framework)
						{
							return (framework.name == frameworkName)
						});

						if (framework == undefined)
						{
							entityos.invoke('util-end', 
							{
								error: 'Invalid framework'
							},
							'403');
						}
						else
						{
							let didMethodName = _.get(data, 'didmethod');

							if (didMethodName == undefined)
							{
								didMethodName = frameworkName;
							}

							const didMethod = _.find(framework.did.methods, function (method)
							{
								return (method.name == didMethodName)
							});

							if (didMethod == undefined)
							{
								entityos.invoke('util-end', 
								{
									error: 'Invalid didmethod'
								},
								'403');
							}
							else
							{	
								const didMethodSpecification = _.find(settings.ssi.specifications, function (specification)
								{
									return (specification.name == didMethod.specification)
								});

								if (didMethodSpecification == undefined)
								{
									entityos.invoke('util-end', 
									{
										error: 'Invalid didmethod.specification'
									},
									'403');
								}
								else
								{
									let curveType = _.get(data, 'curve');

									if (curveType == undefined)
									{
										curveType = didMethodSpecification.curve;
									}

									let curveKeys = _.get(param, 'curveKeys');
									let useentityOSKeys = _.get(param, 'useentityOSKeys', false);

									if (curveKeys == undefined && useentityOSKeys)
									{		
										const signPublicKeyHex = _.get(settings, 'protect.sign.publicKeyHex');
										const signPrivateKeyHex = _.get(settings, 'protect.sign.privateKeyHex');

										//console.log(signPublicKeyHex)
										//console.log(signPrivateKeyHex)

										if (signPrivateKeyHex == undefined || signPublicKeyHex == undefined)
										{}
										else	
										{
											curveKeys =
											{
												public: {hex: signPublicKeyHex},
												private: {hex: signPrivateKeyHex}
											}
										}
									}

									curveKeys.public.base58 = entityosProtect.convert(
									{
										input: 'hex',
										output: 'base58',
										text: curveKeys.public.hex
									}).textConverted;

									curveKeys.public.sha256Hex = entityosProtect.hash(
									{
										output: 'hex',
										text: curveKeys.public.hex
									}).textHashed;

									const ssiDID = 'did:' + didMethodName + ':' + curveKeys.public.base58;
									
									const multibasePrefixes =
									{
										base58: 'z',
										base16: 'f',
										hex: 'f',
										base32: 'b',
										base64: 'Q',
										base64padding: 'm',
										base64urlsafe: 'u'
									}
								
									let didDocument = {
										id: ssiDID,
										verificationMethod:
										[
											{
												id: ssiDID + '#keys-1',
												type: didMethodSpecification.keyVerificationType,
												controller: ssiDID
										}],
										authentication: [{
											type: didMethodSpecification.keyAuthenticationType,
											publicKey: ssiDID + '#keys-1'
										}],
										service: []
									}

									_.each(didDocument.verificationMethod, function (method)
									{
										if (_.includes(didMethodSpecification.publicKey.name, 'Multibase'))
										{
											method[didMethodSpecification.publicKey.name] =
												multibasePrefixes[didMethodSpecification.publicKey.encoding] +
												curveKeys.public[didMethodSpecification.publicKey.encoding];
										}
										else
										{
											method[didMethodSpecification.publicKey.name] = curveKeys.public[didMethodSpecification.publicKey.encoding];
										}
									});

									didDocument['@context'] = 'https://www.w3.org/ns/did/v1';

										didDocument.service.push(
									{
										id: ssiDID + '#did-resolver-service',
										type: 'DIDResolver',
										serviceEndpoint: 'http://ssi.api.entityos.cloud/get-did-document'
									});

									didDocument.service.push(
									{
										id: ssiDID + '#did-revocation-status-service',
										type: 'RevocationList2020',
										serviceEndpoint: 'http://ssi.api.entityos.cloud/get-did-revocation-status'
									});

									didDocument.service.push(
									{
										id: ssiDID + '#credential-status-service',
										type: 'CredentialStatusList2020',
										serviceEndpoint: 'http://ssi.api.entityos.cloud/get-verifiable-credential-status'
									});
									
									//console.log(didDocument)

									const didDocumentFormatted = JSON.stringify(didDocument, null, 2)

									let responseData =
									{
										"did": 
										{
											"document": didDocument,
											"documentFormatted": didDocumentFormatted
										}
									}

									return responseData

								}
							}
						}
					}
				}
			});

			// !!!! APP STARTS HERE; Initialise the app; app-init invokes app-start if authentication OK
			entityos.invoke('app-init');
		}	
   });

  	return promise
}