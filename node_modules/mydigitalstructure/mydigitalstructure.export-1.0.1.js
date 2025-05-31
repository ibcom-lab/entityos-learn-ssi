var _ = require('lodash')
var moment = require('moment');
var mydigitalstructure = require('mydigitalstructure/mydigitalstructure.js');
var XLSX = require('xlsx/xlsx.js');
var request = require('request');

module.exports = 
{
	VERSION: '1.0.1',

	data: {},

	sheet:
	{
		data: {},

		init: function (param)
		{
			var filename = mydigitalstructure._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
			var exportData = mydigitalstructure._util.param.get(param, 'data').value;
			var templateAttachment = mydigitalstructure._util.param.get(param, 'templateAttachment').value;
			var store = mydigitalstructure._util.param.get(param, 'store', {default: true}).value;

			mydigitalstructure._util.param.set(param, 'exportData', exportData);

			var url = mydigitalstructure._util.param.get(param, 'url').value; 

			if (url == undefined)
			{
				if (templateAttachment != undefined)
				{
					var settings = mydigitalstructure.get({scope: '_settings'});
					var session = mydigitalstructure.data.session;

					url = 'https://' + settings.mydigitalstructure.hostname + '/rpc/core/?method=CORE_ATTACHMENT_DOWNLOAD&id=' + templateAttachment +
							'&sid=' + session.sid + '&logonkey=' + session.logonkey;
				}
			}

			var exportFormats = mydigitalstructure._util.param.get(param, 'formats').value; 

			if (url == undefined)
			{
				mydigitalstructure._util.log.add(
				{
					message: 'mydigitalstructure._util.export.sheet; no template URL'
				});
			}
			else
			{
				request(url, {encoding: null}, function(err, res, data)
				{
					if (err || res.statusCode !== 200)
					{
						console.log(err);
					}

					var workbook = XLSX.read(data, {type:'buffer', cellStyles: true, bookImages: true});

				  	var sheetData = {};

				  	if (workbook.Workbook != undefined)
				  	{
					  	sheetData.names = workbook.Workbook.Names;

					  	_.each(sheetData.names, function (name)
					  	{
					  		name.sheet = _.replaceAll(_.first(_.split(name.Ref, '!')), "'", '');
							name.cell = _.replaceAll(_.last(_.split(name.Ref, '!')), '\\$', '');

					  		_.each(exportFormats, function (format)
							{
								if (format.name != undefined)
								{
									if (format.name.toLowerCase() == name.Name.toLowerCase() 
											&& format.sheet == name.sheet)
									{
			   						format.cell = name.cell;
									}
								}
							});
					  	});
					}

				  	// GO THROUGH FORMATS AND WRITE VALUES TO WORKSHEETS

				  	var worksheet;
				  	var cell;
				  	var value;

				  	_.each(exportFormats, function (format)
				  	{
				  		if (format.sheet != undefined)
				  		{
					  		value = format.value;

					  		if (format.storage != undefined)
					  		{
				  				var storageData = _.find(exportData, function (data)
								{
									return data.field == format.storage.field;
								});

								if (storageData != undefined)
								{
									if (storageData.value != undefined)
									{
										value = _.unescape(_.unescape(storageData.value))
									}
								}
					  		}

						  	worksheet = workbook.Sheets[format.sheet];

						  	if (worksheet != undefined)
						  	{
						  		cell = worksheet[format.cell];

								if (cell == undefined)
								{
									cell = {};
								}

								cell.t = 's';

								if (format.type != undefined)
								{
									cell.t = format.type;
								}
							
								cell.v = (value!=undefined?value:'');
							}
						}
					});

				  	sheetData.workbook = workbook;

				  	//https://github.com/sheetjs/sheetjs#writing-options
			
					if (true)
					{
						sheetData.base64 = XLSX.write(workbook, {type: 'base64', cellStyles: true, bookImages: true});
						sheetData.array = XLSX.write(workbook, {type: 'array', cellStyles: true, bookImages: true});
						sheetData.buffer = XLSX.write(workbook, {type: 'buffer', cellStyles: true, bookImages: true});

						module.exports.sheet.store.save(param,
						{
							base64: sheetData.base64,
							binary: sheetData.binary,
							array: sheetData.array,
							buffer: sheetData.buffer
						});
					}	
					else
					{
						//For debugging;
						XLSX.writeFile(workbook, 'checklist-debug.xlsx', {cellStyles: true, bookImages: true});
					}				
				});
			}
		},

		store:
		{
			save: function (param, fileData)
			{
				var filename = mydigitalstructure._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
				var object = mydigitalstructure._util.param.get(param, 'object', {default: 107}).value;
				var objectContext = mydigitalstructure._util.param.get(param, 'objectContext').value;
				var base64 = mydigitalstructure._util.param.get(param, 'base64', {default: false}).value;
				var type = mydigitalstructure._util.param.get(param, 'type').value;

				if (base64)
				{
					mydigitalstructure.cloud.invoke(
					{
						method: 'core_attachment_from_base64',
						data:
						{
							base64: fileData.base64,
							filename: filename,
							object: object,
							objectcontext: objectContext
						},
						callback: module.exports.sheet.store.process,
						callbackParam: param
					});
				}
				else
				{
					var settings = mydigitalstructure.get({scope: '_settings'});
					var session = mydigitalstructure.data.session;

					var blob = Buffer.from(fileData.buffer)

					var FormData = require('form-data');
					var form = new FormData();
		
					form.append('file0', blob,
					{
						contentType: 'application/octet-stream',
						filename: filename
					});
					form.append('filename0', filename);
					form.append('object', object);
					form.append('objectcontext', objectContext);
					form.append('method', 'ATTACH_FILE');
					form.append('sid', session.sid);
					form.append('logonkey', session.logonkey);

					if (!_.isUndefined(type))
					{
						form.append('type0', type);
					}

					var url = 'https://' + settings.mydigitalstructure.hostname + '/rpc/attach/'

					form.submit(url, function(err, res)
					{
						res.resume();

						res.setEncoding('utf8');
						res.on('data', function (chunk)
						{
							var data = JSON.parse(chunk);
						   module.exports.sheet.store.process(param, data)
						});
					});
				}
			},

			process: function (param, response)
			{
				var controller = mydigitalstructure._util.param.get(param, 'controller').value;

				if (response.status == 'OK')
				{
					var attachment;

					if (_.has(response, 'data.rows'))
					{
						attachment = _.first(response.data.rows);
					}
					else
					{
						attachment = response;
					}

					var data =
					{
						attachment:
						{
							id: attachment.attachment,
							link: attachment.attachmentlink,
							href: '/download/' + attachment.attachmentlink
						}
					}
				}

				param = mydigitalstructure._util.param.set(param, 'data', data);

				module.exports.sheet.store.complete(param)
				
			},
		
			complete: function (param)
			{
				mydigitalstructure.invoke('app-process-add-scheduled-audit-process-checklist-send', param)
			}
		}
	}
	
}