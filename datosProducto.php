<?php

/**
 * Buscador de Producto Informático y sus vulnerabilidades reconocidas.
 *
 * Este script permite buscar información sobre productos informáticos y obtener sus vulnerabilidades conocidas.
 * Utiliza múltiples fuentes y técnicas de scraping para recopilar y presentar la información de manera detallada.
 *
 * @version 0.1.5 Alpha
 * @author AJ Melian
 * @date 2024-06-05
 */

/**
 * Obtiene el contenido de una URL utilizando cURL.
 *
 * @param string $url La URL a obtener.
 * @param array $context Las opciones de contexto para la solicitud.
 * @return string El contenido de la respuesta.
 */
function fetchUrl($url, $context) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $context['http']['header']);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

/**
 * Función principal que procesa un producto y obtiene sus vulnerabilidades.
 *
 * @param string $product El nombre del producto a buscar.
 * @return void
 */
function processProduct($product) {
    $options = [
        'http' => [
            'header' => [
                "Accept-language: en",
                "Cookie: foo=bar",
                "User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.102011-10-16 20:23:10"
            ]
        ]
    ];
    $context = ['http' => ['header' => $options['http']['header']]];
    $data = [];
    $finish = 0;

    if (preg_match('/^[\w ]{1,}[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3}(\.[0-9]{1,3}))?(\-(alpha|beta|preview|rc))?(\.[0-9]{1,3})?$/m', $product)) {
        $data['product'] = $product;
        $url = 'https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword=' . urlencode($product);
        $res = fetchUrl($url, $context);
        preg_match_all("/cpe:2\.3:[aho](?::(?:[a-zA-Z0-9!#$%&'()*+,-_.\/;<=>?@\[\]^`{|}~]|:)+){10}/", $res, $results, PREG_OFFSET_CAPTURE);
        $list = array_unique(array_map('strip_tags', array_map('trim', array_column($results[0], 0))));
        $data['cpe'] = $list[0] ?? null;
    } else {
        while (in_array($finish, [0, 1, 2])) {
            $html = fetchUrl("https://www.cvedetails.com/version-search.php?page=1&product=" . urlencode($product), $context);
            if (strpos($html, "No matches") !== false) {
                $finish++;
            } else {
                $html = preg_split("/\r\n|\n|\r/", $html);
                for ($i = 300; $i < count($html); $i++) {
                    $html[$i] = str_replace("\t", "", $html[$i]);
                    if (str_contains($html[$i], 'Version Details</a>')) {
                        $ini = strpos($html[$i], 'title="');
                        $end = strpos($html[$i], '"', $ini + 7);
                        $product = explode('"', substr($html[$i], $ini, $end))[1];
                        $product = substr($product, (strpos($product, ' ') + 1));
                        $data['product'] = $product;
                        $ini = strpos($html[$i], 'href="');
                        $end = strpos($html[$i], '"', $ini + 6);
                        $url = "https://www.cvedetails.com" . explode('"', substr($html[$i], $ini, $end))[1];
                        unset($html);
                        $html = fetchUrl($url, $context);
                        preg_match_all("/cpe:2\.3:[aho](?::(?:[a-zA-Z0-9!#$%&'()*+,-_.\/;<=>?@\[\]^`{|}~]|:)+){10}/", $html, $cpe, PREG_OFFSET_CAPTURE);
                        $data['cpe'] = strip_tags($cpe[0][0][0]);
                        break;
                    }
                }
                $finish = 3;
            }
            switch ($finish) {
                case 1:
                    if ((str_word_count($product) > 1) && (substr($product, -1) == "d")) {
                        $product = substr($product, 0, -1);
                    }
                    break;
                case 2:
                    if ((str_word_count($product) > 1)) {
                        $product = trim(explode(" ", $product)[0]);
                    }
                    break;
            }
        }
    }

    if (isset($data['cpe'])) {
        $url = 'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&isCpeNameSearch=true&seach_type=all&query=' . urlencode($data['cpe']);
        $cpe = fetchUrl($url, $context);
        preg_match_all('/CVE-(1999|2\d{3})-(?!0{4})(0\d{2}[0-9]|[1-9]\d{3,})/', $cpe, $results, PREG_OFFSET_CAPTURE);
        $list = [];
        foreach ($results[0] as $row) {
            if (!in_array($row[0], $list)) {
                $list[] = $row[0];
            }
        }
        if (empty($list)) {
            echo "No vulnerabilities for this product!" . PHP_EOL;
        } else {
            foreach ($list as $cve) {
                $cve = strtoupper($cve);
                $report = ['code' => $cve];
                $html = preg_split("/\r\n|\n|\r/", fetchUrl("https://www.cvedetails.com/cve/" . $cve . "/", $context));
                if (str_contains($html[8], $cve)) {
                    for ($i = 0; $i < count($html); $i++) {
                        $html[$i] = str_replace("\t", "", $html[$i]);
                        if (str_contains($html[$i], '<main>')) {
                            $ini = $i;
                        }
                        if (str_contains($html[$i], '</main>')) {
                            $fin = $i;
                        }
                    }
                    $html = array_slice($html, ($ini + 1), ($fin - $ini - 1));
                    for ($i = 0; $i < count($html); $i++) {
                        if (str_contains($html[$i], "cvedetailssummary")) {
                            $report['desc'] = htmlentities(strip_tags($html[$i]));
                        }
                        if (str_contains($html[$i], "CISA")) {
                            if (str_contains($html[$i], "CISA vulnerability name:")) {
                                $report['name'] = htmlentities($html[$i + 2]);
                            }
                            if (str_contains($html[$i], "CISA required action:")) {
                                $report['action'] = htmlentities($html[$i + 2]);
                            }
                            if (str_contains($html[$i], "CISA description:")) {
                                if (strlen(htmlentities(strip_tags($html[$i + 2]))) > 10) {
                                    $report['desc'] = htmlentities(strip_tags($html[$i + 2]));
                                }
                            }
                        }
                        if (str_contains($html[$i], ">Published</span>")) {
                            $report['dates']['published'] = str_replace("</div>", "", $html[$i + 1]);
                        }
                        if (str_contains($html[$i], ">Updated</span>")) {
                            $report['dates']['updated'] = str_replace("</div>", "", $html[$i + 1]);
                        }
                        if (str_contains($html[$i], 'ssc-vuln-cat')) {
                            if (strpos($html[$i], 'ssc-vuln-cat')) {
                                $ini = strpos($html[$i], '<span class="ssc-vuln-cat">');
                                $temp = explode(">", substr($html[$i], $ini));
                                foreach ($temp as $row) {
                                    if (strlen(strip_tags($row)) > 3) {
                                        $report['categories'][] = strip_tags($row);
                                    }
                                }
                                unset($temp, $ini);
                                $report['categories'] = array_unique($report['categories']);
                            }
                        }
                        if (str_contains($html[$i], "<td") && !isset($report['score'])) {
                            $report['score'] = strip_tags($html[$i + 1]);
                            $report['severity'] = strip_tags($html[$i + 4]);
                            $report['vector'] = strip_tags($html[$i + 8]);
                            $report['score_explotability'] = strip_tags($html[$i + 11]);
                            $report['score_impact'] = strip_tags($html[$i + 14]);
                            $report['source'] = strip_tags($html[$i + 17]);
                            $temp = explode("</div><div>", $html[$i + 24]);
                            foreach ($temp as $row) {
                                $x = explode(": ", $row);
                                $report['cvss_data'][strip_tags(str_replace(" ", "_", $x[0]))] = strip_tags($x[1]);
                            }
                        }
                        unset($temp);
                        if (str_contains($html[$i], "<td") && str_contains(strip_tags($html[$i + 8]), "CVSS")) {
                            $report['score'] = strip_tags($html[$i + 1]);
                            $report['severity'] = strip_tags($html[$i + 4]);
                            $report['vector'] = strip_tags($html[$i + 8]);
                            $report['score_explotability'] = strip_tags($html[$i + 11]);
                            $report['score_impact'] = strip_tags($html[$i + 14]);
                            $report['source'] = strip_tags($html[$i + 17]);
                            $temp = explode("</div><div>", $html[$i + 24]);
                            foreach ($temp as $row) {
                                $x = explode(": ", $row);
                                $report['cvss_data'][strip_tags(str_replace(" ", "_", $x[0]))] = strip_tags($x[1]);
                            }
                        }
                        unset($temp);
                        if (isset($html[$i]) && str_contains($html[$i], 'ssc-ext-link')) {
                            preg_match_all('/https?\:\/\/[^\" ]+/i', $html[$i], $partes);
                            $report['references'][] = $partes[0][0] ?? null;
                            unset($partes);
                        }
                    }
                    $report['details'] = "https://www.cvedetails.com/cve/" . $cve . "/";
                    print_r($report);
                }
            }
        }
    }
}

/**
 * Ejecuta los procesos de manera paralela o secuencial, dependiendo del soporte de la máquina.
 *
 * @param array $products Lista de productos a procesar.
 * @return void
 */
function runProcesses($products) {
    $maxProcesses = shell_exec('nproc') - 1;
    $maxProcesses = $maxProcesses ? intval($maxProcesses) : 1;
    
    if ($maxProcesses > 1) {
        $children = [];
        foreach ($products as $product) {
            while (count($children) >= $maxProcesses) {
                foreach ($children as $key => $pid) {
                    $res = pcntl_waitpid($pid, $status, WNOHANG);
                    if ($res == -1 || $res > 0) {
                        unset($children[$key]);
                    }
                }
                usleep(100000);
            }
            $pid = pcntl_fork();
            if ($pid == -1) {
                die('No se pudo crear el proceso hijo.');
            } elseif ($pid) {
                $children[] = $pid;
            } else {
                processProduct($product);
                exit(0);
            }
        }
        foreach ($children as $pid) {
            pcntl_waitpid($pid, $status);
        }
    } else {
        foreach ($products as $product) {
            processProduct($product);
        }
    }
}

// Ejemplo de uso
$product = trim(str_replace('"','',$argv[1]));
$product = strip_tags($product);

runProcesses($product);

?>
