<?php
namespace Pydio\Auth\Driver;

use Pydio\Access\Core\Model\Repository;
use Pydio\Auth\Core\AbstractAuthDriver;
use Pydio\Core\Utils\TextEncoder;
use Pydio\Core\Model\ContextInterface;
use Pydio\Core\Services\AuthService;
use Pydio\Core\Services\UsersService;
use Pydio\Core\Services\RepositoryService;
use Pydio\Log\Core\Logger;

defined('AJXP_EXEC') or die('Access not allowed');

require('SoapGroepsadmin.php');

define('WSDL', 'https://groepsadmin.scoutsengidsenvlaanderen.be/groepsadmin/webservice?wsdl');

/**
 * @package AjaXplorer_Plugins
 * @subpackage Auth
 */
class sgvAuthDriver extends AbstractAuthDriver
{
    public $driverName = "sgv";
    private $ga;

    public function init(ContextInterface $ctx, $options = []) {

        parent::init($ctx, $options);

        $this->ga = new \SoapGroepsadmin(WSDL, 'sgv-org', true);
    }

    public function userExists($login) {

        // A message like 'This user does not exist.' should not be shown for security reasons.
        return $login != 'admin'; // 'admin' -> SqlAuthDriver and ajxp_users
    }

    public function usersEditable() {

        return false;
    }

    public function passwordsEditable() {

        return false;
    }

    public function checkPassword($login, $pass) {

        Logger::info(__CLASS__, __FUNCTION__, 'SGV login: ' . $login);

        if (sha1($pass) === $_SERVER["ADMIN_PW_SHA1"]) {
            return true;
        } else if ($login !== 'admin') {
            try {
                $id = $this->ga->login($login, $pass);
            } catch (Exception $e) {
                throw new Exception("Probleem met de koppeling met de groepsadministratie.\n\n".$e->getMessage());
            }
            return gettype($id) === 'string';
        }
    }

    public function getGroepsadminId($login) {

        if ($login === 'admin' || preg_match('/^[0-9a-f]{32}$/', $login)) {
            return $login;
        } else {
            $this->logInfo(__FUNCTION__, 'Looking up id: '.$login);

            try {
                return $this->ga->lidGegevensV3($login, null, null, null, null)->id;
            } catch (Exception $e) {
                throw new Exception("Probleem met de koppeling met de groepsadministratie.\n\n".$e->getMessage());
            }
        }
    }

    public function updateUserObject(&$userObject){

        parent::updateUserObject($userObject);

        if ($userObject->id === 'admin') {
            $userObject->personalRole->setParameterValue("core.conf", "USER_DISPLAY_NAME", 'Admin');
            $userObject->personalRole->setParameterValue("core.conf", "email", 'info@scoutsengidsenvlaanderen.be');
            $userObject->save("superuser"); // save to the database (in ajxp_roles, not in ajxp_users)

            return;
        }

        $last_update = $userObject->personalRole->filterParameterValue("core.conf", "last_update", 'AJXP_REPO_SCOPE_ALL', 0);
        $outdated = $last_update + 300 < time();

        if ($outdated) {
            $this->logInfo(__FUNCTION__, 'User id: ' . $userObject->id);

            try {
                $lidGegevens = $this->ga->lidGegevensV3($userObject->id, true, null, null, true);
            } catch (Exception $e) {
                throw new Exception("Probleem met de koppeling met de groepsadministratie.\n\n".$e->getMessage());
            }

            $name = $lidGegevens->voornaam . ' ' . $lidGegevens->naam;
            $email = $lidGegevens->emailadres;

            $userObject->personalRole->setParameterValue("core.conf", "USER_DISPLAY_NAME", $name);
            $userObject->personalRole->setParameterValue("core.conf", "email", $email);
            $userObject->personalRole->setParameterValue("core.conf", "last_update", time());
            $userObject->personalRole->clearAcls();

            $gebruikersgroepen = $lidGegevens->gebruikersgroepen->gebruikersgroep;
            if ($gebruikersgroepen !== null) {
                foreach ($gebruikersgroepen as $gebruikersgroep) {
                    if (preg_match('/^[A-Z][0-9]{4}[A-Z]/', $gebruikersgroep->id)) {
                        $naam = str_replace('_', ' ', $gebruikersgroep->naam);
                        if ($naam === strtoupper($naam) || $naam === strtolower($naam)) {
                            $naam = ucwords(strtolower($naam));
                        }
                        $enabled = $this->updateRepo($gebruikersgroep->id, $naam);
                        if ($enabled) {
                            $recht = isset($gebruikersgroep->beheersrecht) ? 'rw': 'r';
                            $userObject->personalRole->setAcl($gebruikersgroep->id, $recht);
                        }
                    }
                }
            }
        }

        $userObject->personalRole->setAcl('ajxp_home', 'rw');

        $userObject->save("superuser"); // save to the database (in ajxp_roles, not in ajxp_users)
        AuthService::updateSessionUser($userObject); // reload the rights from the ACL
    }

    private function updateRepo($repo_id, $repo_titel) {

        $repo = RepositoryService::getRepositoryById($repo_id);

        $changed = false;

        if ($repo === null) {
            $this->logInfo(__FUNCTION__, 'New repo: ' . $repo_id);

            $repo = new Repository($repo_id, $repo_titel, 'fs'); # fs -> filesystem
            $repo->uuid = $repo_id;

            RepositoryService::addRepository($repo);

            $repo->path = TextEncoder::toStorageEncoding('/mnt/' . $repo_id);

            $repo->enabled = true;
            $repo->create = false; // created and controlled by an external script
            $repo->isTemplate = false;
            $repo->setInferOptionsFromParent(false);
            $repo->setSlug($repo_id);

            $repo->options["PATH"] = $repo->path; // Both seem to be used
            $repo->options["META_SOURCES"] = array(); // clear old meta settings
            $repo->options["META_SOURCES"]["meta.git"] = array(); // (re)activate the git plugin
            $repo->options["META_SOURCES"]["index.lucene"] = array(
                "index_content" => true,
                "index_meta_fields" => "",
                "repository_specific_keywords" => ""
            );
            $repo->options["META_SOURCES"]["meta.syncable"] = array(
                "REPO_SYNCABLE" => true,
                "OBSERVE_STORAGE_CHANGES" => true,
                "OBSERVE_STORAGE_EVERY" => "60"
            );

            // Indexation (search) is executed as the admin user.
            $adminUser = UsersService::getUserById('admin');
            $adminUser->personalRole->setAcl($repo_id, 'r');
            $adminUser->save("superuser"); // save to the database

            $changed = true;
        }

        $repo_exists = is_dir($repo->path);
        $changed |= ($repo->enabled == $repo_exists);
        $repo->enabled = $repo_exists; // Ignored if not changed

        $changed |= ($repo->display != $repo_titel);
        $repo->display = $repo_titel; // Ignored if not changed
        if (!$repo->enabled) {
            // Ignored if not changed
            $repo->display = '[path not found] ' . $repo->display;
        }

        // Ignored if not changed
        $repo->options["EMAIL"] = strtolower(preg_replace('/((_gouw_)|[\$#@~!&*()\[\];.,:?^ `\'\\\\\/ ])+/', '_', $repo_titel) . '_' . $repo_id) . '@scoutsengidsenvlaanderen.org';

        // TODO: zou niet nodig mogen zijn
        $changed = true;
        $repo->path = TextEncoder::toStorageEncoding('/mnt/' . $repo_id);
        $repo->options["PATH"] = $repo->path; // Both seem to be used

        if ($changed) {
            RepositoryService::replaceRepository($repo_id, $repo);
        }

        return $repo->enabled;
    }

    private function isOutdated($timestamp) {
        return $timestamp + 300 < time();;
    }
}
