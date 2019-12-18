<?php
// Route::delete('banner/{banner}/trash', 'BannerController@trash')->name('banner.trash');
// Route::get('banner/{banner}/restore', 'BannerController@restore')->name('banner.restore');
// Route::post('banner/massTrash', 'BannerController@massTrash')->name('banner.massTrash')->middleware('demoCheck');
use Illuminate\Support\Facades\Route;

Route::post('banner/group/massDestroy', 'BannerGroupController@massDestroy')->name('banner.group.massDestroy')->middleware('demoCheck');
// Route::delete('banner/emptyTrash', 'BannerController@emptyTrash')->name('banner.emptyTrash');
Route::resource('banner.group', 'BannerGroupController', ['except' => ['show']]);