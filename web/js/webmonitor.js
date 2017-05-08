/* TODO:
- sources/links
- slider/calendar picker
*/
(function(ns){
  // config
  ns.transitions = 600;
  ns.selecterHeight = 200;
  ns.selectedExpanded = false;
  ns.selectedVisual = "screen";
  ns.diffExpanded = null;
  ns.currentwin = "copy";

  // internal
  ns.last = ns.versions[ns.versions.length - 1];
  ns.previous = ns.versions[ns.versions.length - 2];
  ns.links = {"orig": null, "copy": null};
  ns.text = {"orig": null, "copy": null};
  ns.mergely = {"links": null, "text": null};

  ns.buildUrl = function(version, typ){
    return ["monitor", ns.channel, ns.name, version+"."+typ].join("/");
  };

  ns.nameVersion = function(version, clean){
    if (clean)
      return new Date(version.replace(/^(..)(..)(..)-(..)(..)$/, "20$1-$2-$3 $4:$5")).toUTCString().replace(/:00 GMT/, "");
    return version.replace(/^(..)(..)(..)-(..)(..)$/, "$3/$2/$1 $4:$5");
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
      (curwin === "copy" ? 'l' : 'r') + 'hs',
      ns[typ][version]
    );
    if (ns[typ]["orig"] && ns[typ]["copy"]) {
      ns.mergely[typ].mergely('scrollToDiff', 'next');
    }
  };

  ns.loadVersion = function(version, curwin){
    var url = ns.buildUrl(version, "html"),
      name = ns.nameVersion(version, true);
    curwin = curwin || ns.currentwin;
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

  ns.loadReal = function(){
    var url = ns.url || "http://regardscitoyens.org";
    $(".selectorig").removeClass('selectorig');
    $(".real").addClass('selectorig');
    $(".orig a").text("live web " + url)
                .attr("href", url);
    $(".orig .content").empty();
    $(".orig iframe").attr("src", url);
  };

  ns.toggleCurrentWindow = function(){
    ns.currentwin = (ns.currentwin === "orig" ? "copy" : "orig");
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
  };

  ns.expandDiff = function(typ){
    if (typ === "visual") {
      $("#fullshots, #iframes .orig, #iframes .copy").animate({height: 3 * ns.pieceHeight - 1}, ns.transitions);
      $("iframe").animate({height: 3 * ns.pieceHeight - 2}, ns.transitions);
    } else {
      $("#diff" + typ).animate({height: 3 * ns.pieceHeight - 2}, ns.transitions);
      $("#diff" + typ + " .differ").height(3 * ns.pieceHeight - 2);
      $(".differ").width($("#selecter").width() + 6);
      ns.mergely[typ].mergely('resize');
    }
  };

  ns.reduceDiff = function(typ){
    if (typ === "visual") {
      $("#iframes .orig, #iframes .copy, iframe").animate({height: 0}, ns.transitions);
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
  };

  ns.toggleVisual = function(){
    ns.selectedVisual = $("input[name=visual]:checked").val();
    if (ns.selectedVisual === "screen") {
      $("#fullshots").show();
      $("#iframes .orig, #iframes .copy").hide();
    } else {
      $("#fullshots").hide();
      $("#iframes .orig, #iframes .copy").show();
    }
  };

  ns.resetDiffHeights = function(animate){
    $("#difflinks, #difftext").animate({'height': ns.pieceHeight}, (animate ? ns.transitions : 0));
    $("#fullshots, #iframes .orig, #iframes .copy").animate({'height': ns.pieceHeight - 1}, (animate ? ns.transitions : 0));
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
      winH = $(window).innerHeight(),
      imgW = Math.max(200, Math.min(350, parseInt(winW/ns.versions.length)));
    $("#selecter").height(ns.selecterHeight - 2);
    $("#selecter_large, #screenshots").width((ns.versions.length) * (imgW + 2) + 1);
    $("#versions p").width(imgW);
    $("#screenshots img").width(imgW - 8);
    ns.diffHeight = winH - ns.selecterHeight - 57;
    ns.selecterMaxHeight = winH - 50;
    ns.pieceHeight = (ns.diffHeight - 22 * 4) / 3;
    $(".differ").width(winW - 10);
    $(".copy iframe, .orig iframe").width((winW - 3) / 2);
    $("#diff").height(ns.diffHeight);
    ns.resetDiffHeights();
  };

  $(document).ready(function(){
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
    /*var p = document.createElement('p');
    p.id = "real";
    p.textContent = "live web";
    $(p).click(ns.loadReal);
    versions.append(p);*/
    ns.setDimensions();
    $("#selecter").scrollLeft($("#selecter_large").width());
    ns.addDiffer("links");
    ns.addDiffer("text");
    ns.loadVersion(ns.previous, "copy");
    ns.loadVersion(ns.last, "orig");
    //ns.loadReal();
    $("input[type=radio][name=curwin]").change(ns.toggleCurrentWindow);
    $("#selecter .expand").click(ns.toggleExpandSelecter);
    ["links", "text", "visual"].forEach(function(typ){
      $("#" + typ + " .expand").click(function(){
        ns.toggleExpandDiff(typ)
      });
    });
    $("input[type=radio][name=visual]").change(ns.toggleVisual);
    $(window).resize(ns.setDimensions);
  });

})(window.gazouilleur = window.gazouilleur || {});
