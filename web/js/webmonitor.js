/* TODO:
- sources/links
- slider/calendar picker
*/
(function(ns){
  // vars inherited from template
  ns.url;
  ns.name;
  ns.channel;
  ns.versions;

  // internal
  ns.imgW;
  ns.last;
  ns.prev;
  ns.transitions = 600;
  ns.selecterHeight = 200;
  ns.links = {"prev": null, "last": null};
  ns.text = {"prev": null, "last": null};
  ns.mergely = {"links": null, "text": null};

  // config
  ns.selectedExpanded = false;
  ns.selectedVisual = "screen";
  ns.diffExpanded = null;
  ns.currentwin = "prev";

  ns.readURLParams = function(){
    var last = ns.versions[ns.versions.length - 1],
      prev = ns.versions[ns.versions.length - 2],
      selectedExpanded = false,
      selectedVisual = "screen",
      diffExpanded = null,
      currentwin = "prev";
    window.location.hash.replace(/^#/, "")
    .split(/&/)
    .forEach(function(opt){
      if (opt === "ls") {
        currentwin = last;
      } else if (opt === "if") {
        selectedVisual = "iframe";
      } else if (opt === "fs") {
        selectedExpanded = true;
      } else if (/(visual|links|text)/.test(opt)) {
        diffExpanded = opt;
      } else if (/^prev=/.test(opt)) {
        prev = opt.replace(/^prev=/, "");
      } else if (/^last=/.test(opt)) {
        last = opt.replace(/^last=/, "");
      }
    });
    ns.setDimensions();
    if (currentwin !== ns.currentwin)
      ns.toggleCurrentWindow(currentwin);
    if (selectedVisual !== ns.selectedVisual)
      ns.toggleVisual(selectedVisual);
    if (selectedExpanded !== ns.selectedExpanded)
      ns.toggleExpandSelecter();
    if (diffExpanded !== ns.diffExpanded)
      ns.toggleExpandDiff(diffExpanded);
    if (prev !== ns.prev)
      ns.loadVersion(prev, "prev");
    if (last !== ns.last)
      ns.loadVersion(last, "last");
    $("#selecter").scrollLeft((ns.imgW + 2) * (ns.versions.indexOf(last)-2));
  };

  ns.updateURLParams = function(){
    window.location.hash = [
      ns.currentwin === "last" ? "ls" : null,
      ns.selectedVisual === "iframe" ? "if" : null,
      ns.selectedExpanded ? "fs" : null,
      ns.diffExpanded ? ns.diffExpanded : null,
      ns.prev && ns.prev !== ns.versions[ns.versions.length - 2] ? "prev=" + ns.prev : null,
      ns.last && ns.last !== ns.versions[ns.versions.length - 1] ? "last=" + ns.last : null
    ].filter(function(e){return e})
    .join("&");
  };

  ns.buildUrl = function(version, typ){
    return ["monitor", ns.channel, ns.name, version+"."+typ].join("/");
  };

  ns.nameVersion = function(version, clean){
    var dat = new Date(version.replace(/^(..)(..)(..)-(..)(..)$/, "20$1-$2-$3 $4:$5"));
    if (clean) {
      dat.setTime(dat.getTime() - dat.getTimezoneOffset()*60*1000);
      return dat.toGMTString().replace(/:00 GMT/, "");
    }
    return dat.toLocaleString().replace(/:00$/, "");
  };

  ns.addDiffer = function(typ){
    ns.mergely[typ] = $("#mergely-" + typ);
    ns.mergely[typ].width($("#mergely-" + typ).width() + 1);
    ns.mergely[typ].mergely({
      width: 'auto',
      height: 'auto',
      cmsettings: {
        readOnly: true,
        mode: 'text/plain',
        lineNumbers: true,
        lineWrapping: true
      },
      ignorews: true,
      viewport: true,
      bgcolor: "#ddeeff",
      fgcolor: {
        a: "lightgreen",
        c: "lightblue",
        d: "lightpink"
      }
    });
  };

  ns.updateDiffer = function(typ, curwin, version){
    ns[typ][curwin] = ns[typ][version];
    ns.mergely[typ].mergely(
      (curwin === "last" ? 'l' : 'r') + 'hs',
      ns[typ][version]
    );
    if (ns[typ]["prev"] && ns[typ]["last"]) {
      ns.mergely[typ].mergely('scrollToDiff', 'next');
    }
    ns.updateURLParams();
  };

  ns.loadVersion = function(version, curwin){
    curwin = curwin || ns.currentwin;
    if (!version || ns[curwin] === version) return;
    ns[curwin] = version;
    var url = ns.buildUrl(version, "html"),
      name = ns.nameVersion(version, true);
    $(".select" + curwin).removeClass('select' + curwin);
    $("." + version).addClass('select' + curwin);
    $("." + curwin + " .name").text(name)
    $("." + curwin + " a").attr("href", url);
    $("." + curwin + " iframe").attr("src", url);
    $("#screen" + curwin).attr("src", ns.buildUrl(version, "png"));
    ["links", "text"].forEach(function(typ){
      ns.mergely[typ].mergely('scrollTo', 'l', 0);
      ns.mergely[typ].mergely('scrollTo', 'r', 0);
      if (ns[typ][version]) {
        ns.updateDiffer(typ, curwin, version);
      } else $.ajax({
        url: ns.buildUrl(version, typ.replace('e', '')),
        dataType: "text",
        success: function(result){
          ns[typ][version] = result;
          ns.updateDiffer(typ, curwin, version);
        }
      });
    });
  };

  ns.toggleCurrentWindow = function(val){
    if (typeof(val) === "string") {
      ns.currentwin = val;
      $("#curwin-" + val[0]).attr("checked", "checked");
    } else ns.currentwin = $("input[name=curwin]:checked").val();
    ns.updateURLParams();
  };

  ns.toggleExpandButton = function(sel, reduce){
    $("#" + sel + " .expand").attr("title", reduce ? "Reduce" : "Expand");
    $("#" + sel + " .expand .glyphicon")
      .removeClass("glyphicon-resize-" + (reduce ? "full" : "small"))
      .addClass("glyphicon-resize-" + (reduce ? "small" : "full"));
  };

  ns.toggleExpandSelecter = function(){
    ns.selectedExpanded = !ns.selectedExpanded;
    ns.toggleExpandButton("selecter", ns.selectedExpanded);
    if (ns.selectedExpanded) {
      $("#diff").hide();
      $("#selecter").animate({height: ns.selecterMaxHeight}, ns.transitions);
    } else {
      setTimeout(function(){
        $("#diff").show();
      }, ns.transitions);
      $("#selecter").animate({height: ns.selecterHeight - 2}, ns.transitions);
    }
    ns.updateURLParams();
  };

  ns.expandDiff = function(typ){
    if (typ === "visual") {
      $("#fullshots, #iframes .prev, #iframes .last").animate({height: 3 * ns.pieceHeight - 2}, ns.transitions);
      $("iframe").animate({height: 3 * ns.pieceHeight - 4}, ns.transitions);
    } else {
      var gap = 3 * ns.pieceHeight - (typ === "text" ? 2 : 5);
      $("#diff" + typ).animate({height: gap}, ns.transitions);
      $("#diff" + typ + " .differ").height(gap);
      $(".differ").width($("#selecter").width() + 6);
      ns.mergely[typ].mergely('resize');
    }
  };

  ns.reduceDiff = function(typ){
    if (typ === "visual") {
      $("#iframes .prev, #iframes .last, iframe").animate({height: 0}, ns.transitions);
      $("#fullshots").animate({height: 0}, ns.transitions);
    } else {
      $("#diff" + typ).animate({height: 0}, ns.transitions);
      $("#diff" + typ + " .differ").height(0);
    }
  };

  ns.toggleExpandDiff = function(typ){
    if (ns.diffExpanded === typ) {
      ns.toggleExpandButton(typ);
      ns.resetDiffHeights(true);
      ns.diffExpanded = null;
    } else {
      ns.toggleExpandButton(ns.diffExpanded);
      ns.toggleExpandButton(typ, true);
      ns.expandDiff(typ);
      ["links", "text", "visual"].filter(function(a){
        return a !== typ;
      }).forEach(ns.reduceDiff);
      ns.diffExpanded = typ;
    }
    ns.updateURLParams();
  };

  ns.toggleVisual = function(val){
    if (typeof(val) === "string") {
      ns.selectedVisual = val;
      $("#visual-" + val[0]).attr("checked", "checked");
    } else ns.selectedVisual = $("input[name=visual]:checked").val();
    if (ns.selectedVisual === "screen") {
      $("#fullshots").show();
      $("#iframes .prev, #iframes .last").hide();
    } else {
      $("#fullshots").hide();
      $("#iframes .prev, #iframes .last").show();
    }
    ns.updateURLParams();
  };

  ns.resetDiffHeights = function(animate){
    $("#difflinks, #difftext").animate({'height': ns.pieceHeight}, (animate ? ns.transitions : 0));
    $("#fullshots, #iframes .prev, #iframes .last").animate({'height': ns.pieceHeight - 1}, (animate ? ns.transitions : 0));
    $("iframe").animate({'height': ns.pieceHeight - 2}, (animate ? ns.transitions : 0));
    $(".differ").height(ns.pieceHeight);
    if (animate) {
      ["links", "text"].forEach(function(typ){
        ns.mergely[typ].mergely('resize');
      });
    }
  };

  ns.setDimensions = function(){
    var winW = $("#selecter").width(),
      winH = $(window).innerHeight();
    ns.imgW = Math.max(200, Math.min(350, parseInt(winW/ns.versions.length)));
    if (!ns.selectedExpanded)
      $("#selecter").height(ns.selecterHeight - 2);
    $("#selecter_large, #screenshots").width((ns.versions.length) * (ns.imgW + 2) + 1);
    $("#versions p").width(ns.imgW);
    $("#screenshots img").width(ns.imgW - 8);
    ns.diffHeight = winH - ns.selecterHeight - 62;
    ns.selecterMaxHeight = winH - 50;
    ns.pieceHeight = (ns.diffHeight - 22 * 4) / 3;
    $(".differ").width(winW - 20);
    $("#diff").height(ns.diffHeight);
    if (!ns.diffExpanded)
      ns.resetDiffHeights(true);
  };

  ns.loadVersions = function(){
    var versions = $("#versions"),
      screens = $("#screenshots");
    ns.versions.forEach(function(version){
      var textVersion = ns.nameVersion(version),
        p = document.createElement('p'),
        i = document.createElement('img'),
        onclic = function(){
          ns.loadVersion(version);
        };
      p.className = version;
      p.textContent = textVersion;
      i.className = version;
      i.src = ns.buildUrl(version, "png").replace(/.png$/, "-small.png");
      i.title = textVersion;
      i.alt = textVersion;
      versions.append(p);
      screens.append(i);
      $(p).click(onclic);
      $(i).click(onclic);
    });
  };

  $(document).ready(function(){
    // Prepare Mergelys
    ns.addDiffer("links");
    ns.addDiffer("text");

    // Load list of versions and current config
    ns.loadVersions();
    ns.readURLParams();

    // Set events
    //window.onhashchange = ns.readURLParams;
    window.onresize = ns.readURLParams;
    $("input[type=radio][name=curwin]").change(ns.toggleCurrentWindow);
    $("input[type=radio][name=visual]").change(ns.toggleVisual);
    $("#selecter .expand").click(ns.toggleExpandSelecter);
    ["links", "text", "visual"].forEach(function(typ){
      $("#" + typ + " .expand").click(function(){
        ns.toggleExpandDiff(typ);
      });
    });
  });

})(window.gazouilleur = window.gazouilleur || {});
