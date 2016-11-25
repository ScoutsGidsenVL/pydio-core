"use strict";

/* menubalk */

function to_home() {
  if (pydio.user.id == 'admin') {
    pydio.getController().fireAction('switch_to_settings');
  } else {
    pydio.triggerRepositoryChange('ajxp_home');
  }
  return false;
}

function logout() {
  pydio.getController().fireAction("logout");
  return false;
}

function update_account() {
  var loggedIn = typeof pydio != 'undefined' && pydio && pydio.user;
  document.querySelector('.item_registratie').style.display = loggedIn ? 'none' : 'initial';
  document.querySelector('.item_username a').innerHTML = loggedIn ? pydio.user.getPreference('USER_DISPLAY_NAME') : '';
  document.querySelector('.item_username').style.display = loggedIn ? 'initial' : 'none';
  document.querySelector('.item_home').style.display = loggedIn ? 'initial' : 'none';
  document.querySelector('.item_afmelden').style.display = loggedIn ? 'initial' : 'none';
}

setInterval(update_account, 100);
