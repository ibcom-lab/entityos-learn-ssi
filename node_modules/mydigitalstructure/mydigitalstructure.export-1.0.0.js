var _ = require('lodash')
var moment = require('moment');
var XLSX = require('xlsx')

module.exports = 
{
	VERSION: '1.0.0',

	data: {},

	//https://github.com/sheetjs/sheetjs
	//https://github.com/SheetJS/sheetjs/tree/master/demos/server

	/*

	var XLSX = require('xlsx'), request = require('request');
	
	request(url, {encoding: null}, function(err, res, data) {
	
	if(err || res.statusCode !== 200) return;

			//data is a node Buffer that can be passed to XLSX.read
			var workbook = XLSX.read(data, {type:'buffer'});

			// DO SOMETHING WITH workbook HERE
		});
	*/

	sheet:
	{
		data: {},

		init: function (param)
		{
			mydigitalstructure._util.import.sheet.data._param = param;

			var controller = mydigitalstructure._util.param.get(param, 'controller').value;
			var scope = mydigitalstructure._util.param.get(param, 'scope').value;
			var context = mydigitalstructure._util.param.get(param, 'context').value;
			var name = mydigitalstructure._util.param.get(param, 'name',  {default: 'export-format'}).value;
			var filename = mydigitalstructure._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
			
			var exportData = mydigitalstructure._util.param.get(param, 'data').value;
			var templateAttachment = mydigitalstructure._util.param.get(param, 'templateAttachment').value;

			var download = mydigitalstructure._util.param.get(param, 'download', {default: false}).value;
			var store = mydigitalstructure._util.param.get(param, 'store', {default: false}).value;

			mydigitalstructure._util.param.set(param, 'exportData', exportData);

			var url = mydigitalstructure._util.param.get(param, 'url').value; 
			if (url == undefined)
			{
				if (templateAttachment != undefined)
				{
					
					url = '/rpc/core/?method=CORE_ATTACHMENT_DOWNLOAD&id=' + templateAttachment;
				}
			}

			var exportFormats = mydigitalstructure._util.param.get(param, 'formats').value; 

			if (exportFormats == undefined) 
			{
				if (scope != undefined)
				{
					exportFormats = mydigitalstructure._util.data.get(
					{
						scope: scope,
						context: context,
						name: name
					});
				}
			}

			if (url == undefined)
			{
				mydigitalstructure._util.log.add(
				{
					message: 'mydigitalstructure._util.export.sheet; no template URL'
				});
			}
			else
			{
				/* Convert to $.ajax with beforeSend: to set responseType */
				var req = new XMLHttpRequest();
				req.open("GET", url, true);
				req.responseType = "arraybuffer";

				req.onload = function(e)
				{
					var data = new Uint8Array(req.response);
				  	var workbook = XLSX.read(data, {type: "array", cellStyles: true, bookImages: true});

				  	//RESOLVE NAMES TO CELLS

				  	if (workbook.Workbook != undefined)
				  	{
					  	mydigitalstructure._util.export.sheet.data.names = workbook.Workbook.Names;

					  	_.each(mydigitalstructure._util.export.sheet.data.names,  function (name)
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

				  	mydigitalstructure._util.export.sheet.data.workbook = workbook;

				  	//https://github.com/sheetjs/sheetjs#writing-options
			
					if (store)
					{
						mydigitalstructure._util.export.sheet.data.base64 = XLSX.write(workbook, {type: 'base64', cellStyles: true, bookImages: true});
						mydigitalstructure._util.export.sheet.data.binary = XLSX.write(workbook, {type: 'array', cellStyles: true, bookImages: true});
						mydigitalstructure._util.export.sheet.store.save(param,
						{
							base64: mydigitalstructure._util.export.sheet.data.base64,
							binary: mydigitalstructure._util.export.sheet.data.binary
						})
					}
					else
					{
						param = mydigitalstructure._util.param.set(param, 'data', mydigitalstructure._util.export.sheet.data)
						mydigitalstructure._util.onComplete(param);
					}
					
					if (download)
					{
						XLSX.writeFile(workbook, filename, {cellStyles: true, bookImages: true}
					);}
					
					//If email: true then process the automation task by name - once moved to myds util
					
				}

				req.send();
			}
		},

		store:
		{
			save: function (param, fileData)
			{
				var filename = mydigitalstructure._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
				var object = mydigitalstructure._util.param.get(param, 'object').value;
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
						callback: mydigitalstructure._util.export.sheet.store.process,
						callbackParam: param
					});
				}
				else
				{
					var blob = new Blob([fileData.binary], {type: 'application/octet-stream'});

					var formData = new FormData();
					formData.append('file0', blob);
					formData.append('filename0', filename);
					formData.append('object', object);
					formData.append('objectcontext', objectContext);
					if (!_.isUndefined(type))
					{
						formData.append('type0', type);
					}

					$.ajax('/rpc/attach/?method=ATTACH_FILE',
					{
						method: 'POST',
						data: formData,
						processData: false,
						contentType: false,
						success: function(data)
						{
							mydigitalstructure._util.export.sheet.store.process(param, data)
						},
						error: function(data)
						{
							app.notify(data)
						}
					});
				}
			},

			process: function (param, response)
			{
				var controller = mydigitalstructure._util.param.get(param, 'controller').value;
				var compress = mydigitalstructure._util.param.get(param, 'compress', {default: false}).value;

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

					mydigitalstructure._util.export.sheet.data.attachment =
					{
						id: attachment.attachment,
						link: attachment.attachmentlink,
						href: '/download/' + attachment.attachmentlink
					}
				}

				param = mydigitalstructure._util.param.set(param, 'data', mydigitalstructure._util.export.sheet.data);

				if (compress)
				{
					mydigitalstructure._util.export.sheet.store.compress(param)
				}
				else
				{
					mydigitalstructure._util.export.sheet.store.complete(param)
				}
			},
		
			compress: function (param, response)
			{
				var filename = mydigitalstructure._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
				var object = mydigitalstructure._util.param.get(param, 'object').value;
				var objectContext = mydigitalstructure._util.param.get(param, 'objectContext').value;

				var _filename = _.split(filename, '.');
				_filename.pop()

				filename = _.join(_filename, '.') + '-' + moment().format('DDMMMYYYY-HHmm') + '.zip';

				if (response == undefined)
				{
					mydigitalstructure.cloud.invoke(
					{
						method: 'core_attachment_zip',
						data:
						{
							object: object,
							objectcontext: objectContext,
							filename: filename
						},
						callback: mydigitalstructure._util.export.sheet.store.compress,
						callbackParam: param
					});
				}
				else
				{
					if (response.status == 'OK')
					{
						mydigitalstructure._util.export.sheet.data.attachment =
						{
							id: response.attachment,
							link: response.attachmentlink,
							href: '/download/' + response.attachmentlink
						}

						param = mydigitalstructure._util.param.set(param, 'data', mydigitalstructure._util.export.sheet.data);
					}

					mydigitalstructure._util.export.sheet.store.complete(param)
				}
			},

			complete: function (param)
			{
				app.invoke('util-view-spinner-remove', {controller: 'util-export-create-sheet'});	
				mydigitalstructure._util.onComplete(param);
			}
		}
	}
	
}