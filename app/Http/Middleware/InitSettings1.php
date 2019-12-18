<?php
/*   __________________________________________________
    |  Obfuscated by YAK Pro - Php Obfuscator  2.0.1   |
    |              on 2019-11-25 09:02:38              |
    |    GitHub: https://github.com/pk-fr/yakpro-po    |
    |__________________________________________________|
*/

/*
* Copyright (C) Incevio Systems, Inc - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by Munna Khan <help.zcart@gmail.com>, September 2018
*/

namespace App\Http\Middleware;

use App\Helpers\ListHelper;
use Auth;
use Closure;

class InitSettings{
	public function handle($request, Closure $next){
		if (!$request->is("\151\x6e\163\164\x61\x6c\x6c\52")) {
			goto BGsP6;
		}
		return $next($request);
		BGsP6:
		$this->can_load();
		setSystemConfig();
		if (!Auth::guard("\167\145\x62")->check()) {
			goto qmk4L;
		}
		if (!$request->session()->has("\x69\x6d\x70\145\x72\163\157\156\141\164\x65\x64")) {
			goto ncFVz;
		}
		Auth::onceUsingId($request->session()->get("\151\155\x70\x65\162\163\157\156\x61\x74\x65\x64"));
		ncFVz:
		if (!(!Auth::guard("\167\x65\142")->user()->isFromPlatform() && Auth::guard("\167\145\x62")->user()->merchantId())) {
			goto d6QZg;
		}
		setShopConfig(Auth::guard("\x77\145\142")->user()->merchantId());
		d6QZg:
		$permissions = ListHelper::authorizations();
		$permissions = isset($extra_permissions) ? array_merge($extra_permissions, $permissions) : $permissions;
		config()->set("\x70\x65\x72\155\x69\x73\163\x69\x6f\x6e\163", $permissions);
		if (!Auth::guard("\x77\x65\142")->user()->isSuperAdmin()) {
			goto Y1pxl;
		}
		$slugs = ListHelper::slugsWithModulAccess();
		config()->set("\x61\165\164\150\123\154\x75\147\x73", $slugs);
		Y1pxl: qmk4L:
		if ($request->ajax()) {
			goto B7MKR;
		}
		updateVisitorTable($request);
		B7MKR:
		return $next($request);
	}

	private function can_load(){
		if (!(ZCART_MIX_KEY != "\67\x32\x64\143\x36\143\144\x33\x34\63\142\141\x33\61\x36\x63\70\x38\143\146\144\x31\62\144\x39\x37\141\x65\x35\x62" || md5_file(base_path() . "\x2f\x62\157\157\164\x73\x74\x72\x61\x70\x2f\141\x75\x74\157\154\x6f\141\x64\x2e\160\150\x70") != "\143\x39\x33\144\x32\61\x38\70\60\x34\61\x64\146\70\x36\60\63\x64\x64\x65\145\61\x34\62\x31\x31\64\143\x37\63\61\x61")) {
			goto qaZzW;
		}
		die("\104\151\144\40\x79\157\x75\40" . "\x72\x65\155\x6f\x76\145\40\164\150\145\x20" . "\x6f\x6c\144\x20\x66\151\x6c\145\163\40" . "\x21\x3f");
		qaZzW:
		//incevioAutoloadHelpers(getMysqliConnection());
	}
}